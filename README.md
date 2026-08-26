# Edge-Native Guardrails SDK

High-performance, zero-latency guardrail engine written in Rust and C++.

## Features
- Zero-Latency Evaluation
- Offline-First Persistence (SQLite)
- Payload Sanitization & Secret Masking
- Live Telemetry Dashboard

## Structure
- `src/` - Core Rust engine
- `cpp/` - C++ Bridge
- `tests/` - Stress & Integration tests
- `dashboard_server.py` - Real-time monitor UI

## Usage
```bash
cargo build --release
cargo test
python3 dashboard_server.py
```
