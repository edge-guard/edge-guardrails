import time

from edgeguard import EdgeGuard

guard = EdgeGuard(policy_path="policy.yaml")

clean_prompt = "The quick brown fox jumps over the lazy dog and writes clean code."

# 1. Warm-up
for _ in range(10000):
    guard.scan(clean_prompt)

# 2. One-Shot Scan Benchmark (100,000 runs)
N = 100000
start = time.perf_counter()
for _ in range(N):
    guard.scan(clean_prompt)
end = time.perf_counter()

total_time = end - start
latency_us = (total_time / N) * 1_000_000
ops_per_sec = N / total_time

print("==========================================")
print("     EDGEGUARD PERFORMANCE BENCHMARK      ")
print("==========================================")
print(f"Total Iterations : {N:,}")
print(f"Average Latency  : {latency_us:.2f} µs (microseconds)")
print(f"Throughput       : {ops_per_sec:,.0f} scans / sec")

# 3. Streaming Token Scan Benchmark (100,000 tokens)
stream = guard.create_stream_scanner(window_size=256)
token = " instruction "

for _ in range(1000):
    stream.feed_token(token)

start = time.perf_counter()
for _ in range(N):
    stream.feed_token(token)
end = time.perf_counter()

stream_latency_us = ((end - start) / N) * 1_000_000
stream_ops = N / (end - start)

print("------------------------------------------")
print("          STREAMING TOKEN SCAN            ")
print("------------------------------------------")
print(f"Token Latency    : {stream_latency_us:.2f} µs per token")
print(f"Token Throughput : {stream_ops:,.0f} tokens / sec")
print("==========================================")
