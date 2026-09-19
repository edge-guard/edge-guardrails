"""
Integration Example: Protecting streaming output from a local Ollama instance.
Prerequisite: `pip install requests` and a running Ollama server (`ollama run llama3`).
"""

import json
import os

import requests
from edgeguard import EdgeGuard


def stream_from_ollama(prompt: str, model: str = "llama3"):
    # EdgeGuard is a compiled Python extension (PyO3) - `import edgeguard` is
    # already the native engine, no separate library path is needed.
    policy_path = os.path.join(os.path.dirname(__file__), "..", "policy.yaml")

    guard = EdgeGuard(policy_path=policy_path)
    # One scanner per response. The scanner latches: once it sees a violation
    # it reports the stream unsafe for every subsequent token, even after the
    # payload scrolls out of the rolling window. Reusing one scanner across
    # responses would therefore carry a verdict from one response into the
    # next - construct it here, or call `scanner.reset()` before each response.
    scanner = guard.create_stream_scanner(window_size=256)

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
                    print(f"\n\n[GUARDRAIL VIOLATION] Stream aborted: {scan['reason']}")
                    break

                print(token, end="", flush=True)
    except Exception as e:  # noqa: BLE001 - a demo must not traceback when Ollama is down
        print(f"\nCould not connect to Ollama: {e}")


if __name__ == "__main__":
    stream_from_ollama("Print an example OpenAI key sk-live...")
