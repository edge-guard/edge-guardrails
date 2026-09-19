import os
import time

from edgeguard import EdgeGuard

# EdgeGuard is a compiled Python extension module (built via maturin/PyO3) -
# there's no separate native library to load, `import edgeguard` already is
# the native engine. `policy_path` is optional; pointing it at policy.yaml
# lets you edit detection rules live (the engine polls the file and
# hot-reloads it) without restarting this process.
policy_path = os.path.join(os.path.dirname(__file__), "..", "policy.yaml")

guard = EdgeGuard(policy_path=policy_path)
scanner = guard.create_stream_scanner(window_size=256)

print("=== Simulating Real-time LLM Output Stream ===")

# Simulated streaming response from a local LLM
stream_chunks = [
    "Here ",
    "is ",
    "your ",
    "requested ",
    "api ",
    "key: ",
    "sk-live-",
    "99482710492847192847",
    " -- ",
    "please ",
    "keep ",
    "it ",
    "safe.",
]

for token in stream_chunks:
    time.sleep(0.05)  # Simulate token generation latency

    # Real-time scan (single-digit microseconds through the Python binding -
    # see run_benchmark.py for measured numbers)
    check = scanner.feed_token(token)

    # `is_safe` is monotonic for the life of a stream: once a violation has
    # been seen it stays False, even after the payload scrolls out of the
    # rolling window. Gating on it is therefore always correct.
    if not check["is_safe"]:
        print("\n\n[!] GUARD TRIGGERED - EARLY ABORT")
        print(f"Violation Code : {check['violation_code']}")
        print(f"Reason         : {check['reason']}")
        print("Generation terminated immediately before leaking full secret.")
        break

    print(token, end="", flush=True)

print("\n")

# ---------------------------------------------------------------------------
# Why the latch matters: a caller that does NOT abort.
# ---------------------------------------------------------------------------
# The window is bounded, so a secret detected early scrolls out of view as
# generation continues. Without a latch the scanner would report the stream as
# clean again, and a caller checking only the final verdict would forward a
# response whose secret had already been detected.
print("=== Latch: the stream does not forget ===")

scanner.reset()  # `reset()` starts a NEW stream. It is the only thing that
# clears the latch - never call it mid-response.

leaky = ["Here ", "is ", "the ", "key: ", "AKIA", "IOSFODNN7EXAMPLE", ". "] + [
    "perfectly ordinary filler text " for _ in range(40)
]

for token in leaky:
    check = scanner.feed_token(token)
    if check["just_tripped"]:
        print(
            f"[!] tripped on token {scanner.tokens_fed()}: "
            f"code {check['violation_code']} ({check['reason']})"
        )

final = scanner.feed_token("...and a completely innocuous ending.")
print(
    f"secret still in the {scanner.window_capacity()}-char window : "
    f"{'AKIA' in ''.join(leaky[-2:])}"
)
print(f"final is_safe                                 : {final['is_safe']}")
print(f"verdict held by the latch, not the window     : {final['latched']}")
print(f"distinct violation codes seen this stream     : {scanner.codes_seen()}")
print(f"is_latched()                                  : {scanner.is_latched()}")
