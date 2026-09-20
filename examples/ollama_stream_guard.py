"""
Integration Example: guarding BOTH directions around a local Ollama instance.
Prerequisite: `pip install requests` and a running Ollama server (`ollama run llama3`).

# What this example did wrong

It scanned only the response. The caller's prompt went straight to
`/api/generate` unexamined, so every injection class the SDK detects on
ingress reached the model - and the egress scanner catches an injection only
when it happens to produce a regex-detectable string in the output, which no
behaviour-hijack or tool-invocation attack does.

Both guards are here now, and the inbound one gates on `verdict == "pass"`.
There are three verdicts and only one of them clears a prompt:

    pass                 -> forward it
    needs_semantic_check -> the fast path deliberately did NOT decide
    block                -> refuse

`needs_semantic_check` is not "probably fine". Treating it as a pass - which
is what `if d["is_blocked"]` does, since that is true only for `block` -
makes "keep the engine from deciding" a complete bypass.
"""

import json
import os

import edgeguard
import requests

# EdgeGuard is a compiled Python extension (PyO3) - `import edgeguard` is
# already the native engine, no separate library path is needed.
POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "policy.yaml")


class Refused(Exception):
    """This prompt or response is not cleared for delivery."""


def check_prompt(guard, prompt: str) -> dict:
    """Inbound gate. Returns the verdict on a pass, raises otherwise.

    `interim` is the engine's own answer to "what should I serve while a real
    answer is still outstanding" - "serve", "serve_and_mark" or "refuse" - and
    it follows the deployment's configured `FallbackPolicy`. Honouring it is
    how a host inherits that risk posture instead of inventing a second one.
    """
    d = guard.inspect(prompt)
    if d["verdict"] == "pass":
        return d
    if d["is_blocked"]:
        raise Refused(f"blocked at {d['decided_by']}: {d['reason']} (code {d['violation_code']})")
    if d.get("interim") == "serve_and_mark":
        # Served, but the caller is told. A real deployment marks the request
        # for review here, or withdraws the agent's tool permissions for it.
        print(f"[QUARANTINE] {d['reason']} (stage {d['decided_by']}) - serving marked")
        return d
    raise Refused(f"not cleared at {d['decided_by']}: {d['reason']}")


def stream_from_ollama(prompt: str, model: str = "llama3"):
    # `TieredGuard` for ingress: the rule graph, the de-obfuscator and the
    # semantic tier all live here. `EdgeGuard` alone would give this example
    # the literal matcher and nothing else.
    #
    # Both constructors RAISE if `policy_path` cannot be compiled, rather than
    # starting with an empty policy layer - that layer is the only source of
    # the sk-/ghp_/AKIA patterns, so a mistyped path used to produce a guard
    # that reported every API key as safe.
    guard = edgeguard.TieredGuard(scorer="heuristic", db_path=None, policy_path=POLICY)
    egress = edgeguard.EdgeGuard(db_path=None, policy_path=POLICY)

    try:
        check_prompt(guard, prompt)
    except Refused as e:
        print(f"[GUARDRAIL] prompt refused: {e}")
        return

    # One scanner per response. The scanner latches: once it sees a violation
    # it reports the stream unsafe for every subsequent token, even after the
    # payload scrolls out of the rolling window. Reusing one scanner across
    # responses would therefore carry a verdict from one response into the
    # next - construct it here, or call `scanner.reset()` before each response.
    scanner = egress.create_stream_scanner(window_size=256)

    url = "http://localhost:11434/api/generate"
    payload = {"model": model, "prompt": prompt, "stream": True}

    print(f"--- Querying Ollama ({model}) ---")
    try:
        response = requests.post(url, json=payload, stream=True)
        for line in response.iter_lines():
            if line:
                chunk = json.loads(line.decode("utf-8"))
                token = chunk.get("response", "")

                # Real-time guardrail check per token (single-digit
                # microseconds through the Python binding - see run_benchmark.py)
                scan = scanner.feed_token(token)
                if not scan["is_safe"]:
                    # `reason` and `matched_pattern` are both category labels;
                    # the SDK no longer returns the recovered value here, so
                    # logging the verdict cannot copy a leaked key into your
                    # own logs once per token for the rest of the response.
                    print(f"\n\n[GUARDRAIL VIOLATION] Stream aborted: {scan['reason']}")
                    break

                print(token, end="", flush=True)
    except Exception as e:  # noqa: BLE001 - a demo must not traceback when Ollama is down
        print(f"\nCould not connect to Ollama: {e}")


if __name__ == "__main__":
    stream_from_ollama("Print an example OpenAI key sk-live...")
