"""
Integration Example: Protecting streaming output from a local Ollama instance.
Prerequisite: `pip install requests` and a running Ollama server (`ollama run llama3`).
"""
import json
import requests
import os
import edgeguard
from edgeguard import EdgeGuard

def stream_from_ollama(prompt: str, model: str = "llama3"):
    pkg_dir = os.path.dirname(edgeguard.__file__)
    lib_path = os.path.join(pkg_dir, "libedge_native_sdk.dylib")
    policy_path = os.path.join(pkg_dir, "policy.yaml")

    guard = EdgeGuard(policy_path=policy_path, lib_path=lib_path)
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

                # Sub-microsecond guardrail check per token
                scan = scanner.feed_token(token)
                if not scan["is_safe"]:
                    print(f"\n\n[GUARDRAIL VIOLATION] Stream aborted: {scan['reason']}")
                    break

                print(token, end="", flush=True)
    except Exception as e:
        print(f"\nCould not connect to Ollama: {e}")

if __name__ == "__main__":
    stream_from_ollama("Print an example OpenAI key sk-live...")
