from edgeguard import EdgeGuard

guard = EdgeGuard()
stream = guard.create_stream_scanner()

tokens = ["User: ", "Hello! ", "My token is ", "sk-live", "1234567890abcdef12345", " please keep safe."]

print("--- Streaming Tokens ---")
for t in tokens:
    res = stream.feed_token(t)
    is_safe = res["is_safe"]
    reason = res["reason"]
    print(f"Token: {t:<30} -> Safe: {is_safe} (Reason: {reason})")
    if not is_safe:
        print("\n[!] Stream aborted immediately due to policy violation.")
        break
