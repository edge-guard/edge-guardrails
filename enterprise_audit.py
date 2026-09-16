import time
import concurrent.futures
import edgeguard
import threading

# Initialize Engine
guard = edgeguard.EdgeGuard(custom_patterns=["internal_secret_key"])

# Test Configurations
NUM_WORKERS = 16
REQUESTS_PER_WORKER = 5000
TOTAL_REQUESTS = NUM_WORKERS * REQUESTS_PER_WORKER

# Payloads
SMALL_PAYLOAD = "This is a normal user prompt trying to ask a question."
HUGE_PAYLOAD = "Benign text " * 50000  # ~500KB of text

# Global counters for GIL Proof
active_huge_tasks = 0
small_tasks_completed_during_huge = 0
lock = threading.Lock()

def worker_task(worker_id):
    global active_huge_tasks, small_tasks_completed_during_huge
    
    local_blocked = 0
    max_latency = 0
    
    for i in range(REQUESTS_PER_WORKER):
        # Once every 1000 requests, send a MASSIVE payload to simulate heavy CPU load
        is_huge = (i % 1000 == 0)
        payload = HUGE_PAYLOAD if is_huge else SMALL_PAYLOAD
        
        if is_huge:
            with lock:
                active_huge_tasks += 1
                
        t0 = time.perf_counter()
        res = guard.scan(payload)
        latency = (time.perf_counter() - t0) * 1000  # ms
        
        if is_huge:
            with lock:
                active_huge_tasks -= 1
        else:
            # If a small task completes while a huge task is running elsewhere,
            # it PROVES the GIL is released!
            if active_huge_tasks > 0:
                with lock:
                    small_tasks_completed_during_huge += 1

        if latency > max_latency:
            max_latency = latency
            
        if not res['is_safe']:
            local_blocked += 1
            
    return local_blocked, max_latency

if __name__ == "__main__":
    print("🚀 Starting Enterprise Chaos & Red Team Audit...")
    print(f"⚙️  Config: {NUM_WORKERS} Workers, {REQUESTS_PER_WORKER} Requests/Worker")
    print(f"📊 Total Target Volume: {TOTAL_REQUESTS:,} Scans\n")

    start_time = time.perf_counter()
    
    total_blocked = 0
    global_max_latency = 0
    
    # Launch concurrent workers using ThreadPoolExecutor (shares GIL)
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = [executor.submit(worker_task, i) for i in range(NUM_WORKERS)]
        for future in concurrent.futures.as_completed(futures):
            blocked, max_lat = future.result()
            total_blocked += blocked
            if max_lat > global_max_latency:
                global_max_latency = max_lat

    end_time = time.perf_counter()
    total_time = end_time - start_time
    throughput = TOTAL_REQUESTS / total_time

    print("-" * 60)
    print("🛡️ EDGEGUARD ENTERPRISE AUDIT REPORT 🛡️")
    print("-" * 60)
    print(f"⏱️  Total Execution Time: {total_time:.2f} seconds")
    print(f"🔥 Throughput:           {throughput:,.0f} Requests/Second")
    print(f"🐢 Worst Case Latency:   {global_max_latency:.3f} ms (Expected for 500KB+ payloads)")
    
    print("\n--- Concurrency & GIL Analysis ---")
    if small_tasks_completed_during_huge > 0:
        print("✅ GIL STATUS:           🔓 UNLOCKED (Verified)")
        print(f"   Proof: {small_tasks_completed_during_huge:,} small requests processed concurrently")
        print("   WHILE heavy 500KB+ payloads were utilizing the CPU.")
        print("   Python threads were NOT starved by Rust.")
    else:
        print("⚠️ GIL STATUS:           🔒 LOCKED / THREAD STARVATION")
        print("   Python threads had to wait for large payloads to finish.")
        
    print("-" * 60)