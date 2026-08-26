use std::env;
use std::ffi::CString;
use std::time::Instant;

extern "C" {
    fn edge_guardrail_check(text: *const std::os::raw::c_char, len: usize) -> i32;
}

fn check_guardrail(text: &str) -> bool {
    let c_str = CString::new(text).unwrap_or_default();
    unsafe {
        edge_guardrail_check(c_str.as_ptr(), text.len()) != 0
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Edge-Guard: Zero-Latency Local Prompt Security");
        println!("Usage: cargo run --bin cli -- \"<text_to_scan>\"");
        return;
    }

    let input_text = &args[1];
    let start = Instant::now();

    let is_blocked = check_guardrail(input_text);
    let latency = start.elapsed().as_micros();

    println!("\n=== Edge-Guard Scan Result ===");
    println!("Input: \"{}\"", input_text);
    println!("Latency: {} us", latency);

    if is_blocked {
        println!("Status: [BLOCKED] Policy violation detected (PII / API Key / Secret).");
    } else {
        println!("Status: [PASSED] Clean payload.");
    }
    println!("==============================\n");
}
