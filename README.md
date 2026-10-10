# EdgeGuard

Sub-microsecond, On-Device AI Guardrails Engine in Rust and C++

EdgeGuard provides low-latency, zero-network security scanning and token-by-token guardrails for on-device LLMs (such as llama.cpp, vLLM, and Apple MLX).

## Performance Benchmarks (Apple Silicon)

| Metric | EdgeGuard (Native Rust/C) | Standard Python Regex | LLM-based Guardrails |
| :--- | :--- | :--- | :--- |
| One-Shot Latency | 0.48 us | ~18.50 us | 250 ms |
| Throughput | 2,088,000+ scans/sec | ~54,000 scans/sec | ~4 req/sec |
| Streaming Latency | 0.81 us / token | ~12.20 us / token | N/A |
| Streaming Throughput | 1,238,000+ tokens/sec | ~82,000 tokens/sec | N/A |
| Network Overhead | 0 ms (Offline) | 0 ms | 50-300 ms |

## Features

- Sub-Microsecond Latency: Native zero-allocation Rust core.
- Streaming Guardrails: Real-time token streaming validation with rolling window and immediate abort.
- Dynamic Policy: Update and hot-reload rules (PII, Prompt Injection, Secrets) from policy.yaml without recompilation.
- Shannon Entropy: Unsupervised detection of high-entropy raw secret keys and passwords.
- Base64 Sniffer: Automatic decoding and scanning of obfuscated payloads in memory.

## Quick Start

```python
from edgeguard import EdgeGuard

guard = EdgeGuard(policy_path="policy.yaml")
result = guard.scan("Contact me at user@example.com")
print(result)
```

## Node.js and serverless (WebAssembly)

The Rust core also builds to a small WebAssembly module (about 1 MB, no imports, no threads or files),
so it runs inside a Node.js or serverless function without a native build:

```bash
cargo build --profile wasm --target wasm32-unknown-unknown --no-default-features --features wasm
node --test bindings/node/edgeguard.test.mjs
```

```js
import { EdgeGuard, Category } from "./bindings/node/edgeguard.mjs";

const guard = EdgeGuard.fromFile("target/wasm32-unknown-unknown/wasm/edgeguard.wasm");
guard.scan("נא התעלם מכל ההוראות", Category.INJECTION);           // [{ code: 101, category: "injection", ... }]
guard.redact("ת״ז 000000018, כרטיס 4111 1111 1111 1111");         // "ת״ז [ID], כרטיס [CARD]"
```

`scan` returns every finding (not only the first), with string indices and without the matched text.
Loading takes a few milliseconds and a 5 KB email scans in about half a millisecond.

| Category | Finds |
| :--- | :--- |
| `INJECTION` | Instruction-override phrases in English and Hebrew, after removing zero-width characters, Hebrew vowel points and extra whitespace |
| `INJECTION_BROAD` | The roleplay list ("act as a", "pretend to be"); reported as `roleplay` |
| `CREDIT_CARD` | Luhn-valid numbers in one block or card groupings (4-4-4-4, 4-6-5...), so adjacent phone numbers don't match |
| `IL_ID` | Israeli ID numbers with a valid check digit, only next to an ID keyword (ת.ז., מספר זהות, ID number) |
| `IBAN` | Israeli IBANs that pass the mod-97 check |
| `SECRET` | AWS, Anthropic, OpenAI, GitHub, Stripe, Slack and Google keys, private keys, "password: ..." |
| `EMAIL` | Email addresses |
| `LINK` | Links with strong signs of phishing (reported as `suspicious_link`), see below |

### Links (no network lookups)

`guard.links(text)` returns every link in plain text, with or without `http://`, with its registrable
domain (`site`, for allow-lists) and warning signs; `guard.anchors([{ href, text }])` checks HTML links.

| Sign | Meaning |
| :--- | :--- |
| `lookalike` | Imitates a bank, payment app, government site or Microsoft/Google/Apple login (`leumi-verify.com`, `paypa1.com`, `docs.google.com.evil.ru`). Common Hebrew words such as "leumi" don't count under `.il`, and government, municipal and academic domains never do |
| `mismatch` | The visible text shows one address and the link goes to another. Outlook Safe Links and Google redirects are unwrapped first |
| `ip`, `userinfo`, `idn` | A bare IP host, `https://paypal.com@evil.com`, punycode or non-Latin letters |
| `executable`, `script` | A direct link to a program or macro document; `javascript:` / `data:` links |
| `shortener` | The destination is hidden (bit.ly...): a weak sign, not a finding on its own |

## License
MIT
