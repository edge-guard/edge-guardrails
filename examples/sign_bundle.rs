//! Control-plane side signing tool.
//!
//! Lives in `examples/` and not in the library on purpose: the edge SDK
//! should never link code that handles a private key.
//!
//!   cargo run --example sign_bundle -- keygen
//!   cargo run --example sign_bundle -- sign <seed.hex> <key-id> <tenant> <seq> <rules.yaml> <out.egb>
//!   cargo run --example sign_bundle -- verify <trust.txt> <seq-file> <bundle.egb>
use edgeguard::signing::*;
use std::path::Path;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let usage = "usage: sign_bundle keygen | sign <seed.hex> <key-id> <tenant> <seq> <rules.yaml> <out> | verify <trust> <seqfile> <bundle>";
    match a.get(1).map(String::as_str) {
        Some("keygen") => {
            // Deliberately reads seed material from the caller rather than
            // inventing it: real key generation belongs in an HSM or the
            // control plane's KMS, not in a sample binary.
            let seed = std::fs::read("/dev/urandom").ok().and_then(|v| {
                let a: Option<[u8; 32]> = v.get(..32).and_then(|s| s.try_into().ok());
                a
            });
            match seed {
                Some(seed) => {
                    let sk = signing_key_from_bytes(&seed);
                    println!(
                        "seed (KEEP SECRET): {}",
                        seed.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>()
                    );
                    println!("trust store line  : signer-1 {}", public_key_hex(&sk));
                }
                None => eprintln!("could not read seed material"),
            }
        }
        Some("sign") => {
            let (seed_hex, key_id, tenant, seq, rules, out) = (
                &a[2],
                &a[3],
                &a[4],
                a[5].parse::<u64>().expect("seq"),
                &a[6],
                &a[7],
            );
            let seed_bytes = (0..32)
                .map(|i| u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).expect("seed hex"))
                .collect::<Vec<u8>>();
            let sk = signing_key_from_bytes(&seed_bytes.try_into().unwrap());
            let payload = std::fs::read(rules).expect("rules file");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let b = SignedBundle::create(
                &sk,
                key_id,
                &format!("b-{}", seq),
                tenant,
                seq,
                now - 60,
                now + 90 * 86400,
                payload,
            )
            .expect("create");
            std::fs::write(out, b.to_bytes()).expect("write");
            println!("signed {} (seq {}) -> {}", rules, seq, out);
        }
        Some("verify") => {
            let src = SignedRuleSource::from_paths(
                Path::new(&a[2]),
                Path::new(&a[3]),
                VerifyPolicy::default(),
            )
            .expect("provision");
            let r: Result<usize, LoadError<String>> =
                src.load_and_apply(Path::new(&a[4]), |v| Ok(v.payload().len()));
            match r {
                Ok(n) => println!(
                    "OK: accepted {} payload bytes, sequence now {}",
                    n,
                    src.applied_sequence()
                ),
                Err(e) => {
                    eprintln!("REFUSED: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => eprintln!("{}", usage),
    }
}
