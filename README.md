# Edge-Native Guardrails SDK

High-performance, zero-latency guardrails engine written in Rust with C++ FFI bindings. Designed for local LLM inference, on-device policy enforcement, offline buffering, and background telemetry synchronization.

---

## Key Highlights
- **Sub-Millisecond Policy Checks:** In-memory regex compilation and fast-path rule validation avoiding network latency.
- **C++ FFI Bridge:** Seamless integration with native runtimes, embedded systems, and local inference pipelines (e.g., llama.cpp).
- **Offline-First Telemetry:** SQLite local buffer storing audit logs and violation events when offline, with automatic async cloud sync.
- **Built-in Dashboard:** Lightweight real-time event streaming and metrics server.

---

## Quickstart (Rust)

```rust
use edge_guardrails::GuardrailsEngine;

fn main() {
    let engine = GuardrailsEngine::init().expect("Failed to init engine");

    let prompt = "My secret token is sk-live-1234567890abcdef";
    let evaluation = engine.evaluate(prompt);

    if evaluation.is_blocked() {
        println!("Blocked violation: {:?}", evaluation.violations());
    } else {
        println!("Sanitized prompt: {}", evaluation.sanitized_payload());
    }
}
