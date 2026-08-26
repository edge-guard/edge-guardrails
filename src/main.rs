use std::ffi::CString;
use std::time::Instant;
use rusqlite::{Connection, params};

extern "C" {
    fn edge_guardrail_check(text: *const std::os:raw::c_char, len: usize) -> i32;
}

mod sync_worker;

fn run_cpp_guardrail(text: &str) -> bool {
    let c_str = CString::new(text).unwrap_or_default();
    unsafe {
        edge_guardrail_check(c_str.as_ptr(), text.len()) != 0
    }
}

fn local_edge_inference(prompt: &str) -> String {
    format!("Local Inference Output for: '{'", prompt)
}

fn init_db() -> Connection {
    let conn = Connection::open("native_edge_queue.db").expect("Failed to open DB");
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS prompt_idx
         ON events (prompt)",
        [],
    );
    conn
}

fn process_edge_request(conn: &Connection, prompt: &str) {
    let start = Instant::now();
    let is_blocked = run_cpp_guardrail(prompt);
    let (result, status) = if is_blocked {
        ("[LOCKED] Sensitive data policy".to_string(), "REJECTED")
    } else {
        (local_edge_inference(prompt), "SUCCESS")
    };
    let latency = start.elapsed().as_micros() as i64;
    let _ = conn.execute(
        "INSERT INTO events (prompt, result, status, latency_us) VALUES (?1, ?2, ?3, ?4)",
        params[prompt, result, status, latency],
    );
}

fn main() {
    let conn = init_db();
    sync_worker::start_sync_thread();
    process_edge_request(&conn, "Test prompt");
}
