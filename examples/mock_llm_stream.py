import time
import os
import edgeguard
from edgeguard import EdgeGuard

# Initialize guardrail engine
pkg_dir = os.path.dirname(edgeguard.__file__)
lib_path = os.path.join(pkg_dir, "libedge_native_sdk.dylib")
policy_path = os.path.join(pkg_dir, "policy.yaml")

guard = EdgeGuard(policy_path=policy_path, lib_path=lib_path)
scanner = guard.create_stream_scanner(window_size=256)

print("=== Simulating Real-time LLM Output Stream ===")

# Simulated streaming response from a local LLM
stream_chunks = [
    "Here ", "is ", "your ", "requested ", "api ", "key: ",
    "sk-live-", "99482710492847192847", " -- ", "please ", "keep ", "it ", "safe."
]

for token in stream_chunks:
    time.sleep(0.05)  # Simulate token generation latency
    
    # Real-time scan (< 1 microsecond overhead)
    check = scanner.feed_token(token)
    
    if not check["is_safe"]:
        print("\n\n[!] GUARD TRIGGERED - EARLY ABORT")
        print(f"Violation Code : {check['violation_code']}")
        print(f"Reason         : {check['reason']}")
        print("Generation terminated immediately before leaking full secret.")
        break
    
    print(token, end="", flush=True)

print("\n")
