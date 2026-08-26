# ⚡ EdgeGuard Native SDK

**Ultra-low latency, zero-cloud edge guardrails & policy engine for LLMs — powered by Rust & C++ with seamless Python bindings.**

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](https://isocpp.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 🚀 Key Features

- 🏎️ **Microsecond Latency**: Pure native execution (< 5µs scan overhead per prompt).
- 🛡️ **Zero Data Leakage**: 100% on-device local evaluation — prompts never leave the edge runtime.
- 🔒 **Crash-Proof FFI**: Memory-isolated with `catch_unwind` protection against edge panics and buffer overruns.
- 🐍 **Native Python Wrapper**: Drop-in Python integration via `ctypes` bindings.
- 🎯 **Multi-Layer Detection**:
  - PII (Emails, Credit Cards)
  - Secretss, AWS tokens, OpenAI keys)
  - Prompt Injections & Jailbreak patterns

---

## 📦 Python Quickstart

### 1. Build Native Library
```bash
cargo build --lib --release
