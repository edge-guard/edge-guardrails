//! Peak-RSS isolation. Run one operation only, selected by argv[1], so
//! /usr/bin/time -l attributes the footprint to that operation alone.
use edgeguard::deobfuscate::{normalize, NormalizerConfig};
use edgeguard::graph::{baseline_graph, ScanScratch};
use edgeguard::SecurityEngine;
use std::time::Instant;

fn main() {
    let which = std::env::args().nth(1).unwrap_or_else(|| "baseline".into());
    let n = 2_097_152usize;
    match which.as_str() {
        "baseline" => {}
        "norm_clean" => {
            let s = "the quarterly report looks fine. ".repeat(n / 33 + 1);
            let t = Instant::now();
            let r = normalize(&s[..n], &NormalizerConfig::injection());
            println!("borrowed={} took={:?}", r.is_borrowed(), t.elapsed());
        }
        "norm_one_nonascii" => {
            // a SINGLE non-ASCII char in an otherwise clean 2MB prompt
            let mut s = String::from("\u{00e9}");
            s.push_str(&"the quarterly report looks fine. ".repeat(n / 33 + 1)[..n]);
            let t = Instant::now();
            let r = normalize(&s, &NormalizerConfig::injection());
            println!(
                "borrowed={} out_len={} took={:?}",
                r.is_borrowed(),
                r.as_str().len(),
                t.elapsed()
            );
        }
        "norm_zwj" => {
            let s = "i\u{200b}g\u{200b}n\u{200b}o\u{200b}r\u{200b}e\u{200b}".repeat(n / 18 + 1);
            let t = Instant::now();
            let r = normalize(&s, &NormalizerConfig::injection());
            println!(
                "in={} out_len={} took={:?}",
                s.len(),
                r.as_str().len(),
                t.elapsed()
            );
        }
        "norm_spaced" => {
            let s = "i g n o r e ".repeat(n / 12 + 1);
            let t = Instant::now();
            let r = normalize(&s, &NormalizerConfig::injection());
            println!(
                "in={} out_len={} took={:?}",
                s.len(),
                r.as_str().len(),
                t.elapsed()
            );
        }
        "norm_percent" => {
            let s = "%69%67%6e%6f%72%65".repeat(n / 18 + 1);
            let t = Instant::now();
            let r = normalize(&s, &NormalizerConfig::injection());
            println!(
                "in={} out_len={} took={:?}",
                s.len(),
                r.as_str().len(),
                t.elapsed()
            );
        }
        "graph_flood" => {
            let g = baseline_graph();
            let mut sc = ScanScratch::new(&g);
            let s = "ignore ".repeat(n / 7);
            let t = Instant::now();
            let _ = g.evaluate(&s, &mut sc);
            println!("hits={} took={:?}", sc.last_hit_count(), t.elapsed());
        }
        "sanitize_huge" => {
            // 64 MB -- scan() would refuse this at 2 MB; sanitize() has no guard
            let eng = SecurityEngine::new(vec![], None, None);
            let s = "card 4532-0150-0000-0007 ".repeat(64 * 1024 * 1024 / 25);
            println!("input={} MB", s.len() / 1_048_576);
            let t = Instant::now();
            let out = eng.sanitize(&s);
            println!(
                "sanitize returned {} MB in {:?}",
                out.len() / 1_048_576,
                t.elapsed()
            );
        }
        other => println!("unknown: {}", other),
    }
}
