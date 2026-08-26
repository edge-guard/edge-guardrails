use std::ffi::CString;
use std::time::Instant;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

extern "C" {
    fn edge_guardrail_check(text: *const std::os::raw::c_char, len: usize) -> i32;
}

fn check_prompt_cpp(prompt: &str) -> bool {
    let c_str = CString::new(prompt).unwrap_or_default();
    unsafe {
        edge_guardrail_check(c_str.as_ptr(), prompt.len()) != 0
    }
}

fn main() {
    println!("\n🔥 Starting Edge-Native SDK Stress Test (5,000 requests)...");

    let test_prompts = vec![
        "Summarize the quarterly revenue report for Q3",
        "Deploy the backend container using sk_live_998877665544332211secret",
        "Generate a meeting invite for the marketing team",
        "My client SSN is 123-45-6789, please store it in the notes",
        "Optimize the SQL query for table partitions",
        "Customer card payment: 4532112233445566, process immediately",
        "Draft an introduction email for aew enterprise lead",
        "Admin key override: API_SECRET_KEY=ABC123456789XYZ",
        "Calculate the structural wind load for porcelain facade slabs",
        "System prompt test without sensitive data"
    ];

    let total_requests: usize = 5000;
    let blocked_count = Arc::new(AtomicUsize::new(0));
    let passed_count = Arc::new(AtomicUsize::new(0));

    let start_time = Instant::now();

    let num_threads = 8;
    let chunk_size = total_requests / num_threads;
    let mut handles = vec![];

    for t in 0..num_threads {
        let blocked = Arc::clone(&blocked_count);
        let passed = Arc::clone(&passed_count);
        let prompts = test_prompts.clone();

        handles.push(std::thread::spawn(move || {
            for i in 0..chunk_size {
                let p = prompts[(t * chunk_size + i) % prompts.len()];
                if check_prompt_cpp(p) {
                    blocked.fetch_add(1, Ordering::Relaxed);
                } else {
                    passed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let duration = start_time.elapsed();
    let total_seconds = duration.as_secs_f64();
    let tps = total_requests as f64 / total_seconds;
    let avg_latency_us = (duration.as_micros() as f64) / (total_requests as f64);

    println!("\n==================================================");
    println!("📊 STRESS TEST RESULTS");
    println!("==================================================");
    println!("  Total Scans Processed:  {}", total_requests);
    println!("  Blocked (Guardrails):   {}", blocked_count.load(Ordering::SeqCst));
    println!("  Passed (Clean Data):    {}", passed_count.load(Ordering::SeqCst));
    println!("  Total Execution Time:   {:.3} seconds", total_seconds);
    println!("  Throughput (TPS):       {:.2} ops/sec", tps);
    println!("  Average Latency/Scan:   {:.2} \u{00b5}s (microseconds)", avg_latency_us);
    println!("================================================\n");
}
