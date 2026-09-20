//! Adversarial complexity + memory probe. Not a test: it prints curves so a
//! human can see where the engine stops being linear.
use edgeguard::deobfuscate::{normalize, NormalizerConfig};
use edgeguard::graph::{baseline_graph, ScanScratch};
use edgeguard::tier::TieredEngine;
use edgeguard::SecurityEngine;
use std::time::Instant;

fn ns_per_byte<F: FnMut()>(len: usize, iters: u32, mut f: F) -> f64 {
    for _ in 0..2 {
        f();
    }
    let mut best = u128::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        best = best.min(t.elapsed().as_nanos() / iters as u128);
    }
    best as f64 / len as f64
}

fn total_us<F: FnMut()>(iters: u32, mut f: F) -> f64 {
    for _ in 0..2 {
        f();
    }
    let mut best = u128::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        best = best.min(t.elapsed().as_nanos() / iters as u128);
    }
    best as f64 / 1000.0
}

fn main() {
    let sizes = [1_024usize, 16_384, 262_144, 2_097_152];

    println!("== 1. de-obfuscator: ns/byte by input class ==");
    for &n in &sizes {
        let clean = "the quarterly report looks fine. ".repeat(n / 33 + 1);
        let clean = &clean[..n.min(clean.len())];
        // dirty-but-trivial: one non-ASCII char forces the whole owned path
        let mut one_bad = String::from("\u{00e9}");
        one_bad.push_str(clean);
        let zwj = "i\u{200b}g\u{200b}n\u{200b}o\u{200b}r\u{200b}e\u{200b}".repeat(n / 18 + 1);
        let zwj = &zwj[..];
        let spaced = "i g n o r e ".repeat(n / 12 + 1);
        let stretched = "aaaaaaaaaa".repeat(n / 10 + 1);
        let pct = "%69%67%6e%6f%72%65".repeat(n / 18 + 1);
        let cfg = NormalizerConfig::injection();
        let iters = if n > 100_000 { 3 } else { 200 };
        println!(
            "  n={:>9}  clean={:>7.3}  one_nonascii={:>7.3}  zwj={:>7.3}  spaced={:>7.3}  stretch={:>7.3}  pct={:>7.3}",
            n,
            ns_per_byte(n, iters, || { std::hint::black_box(normalize(clean, &cfg)); }),
            ns_per_byte(one_bad.len(), iters, || { std::hint::black_box(normalize(&one_bad, &cfg)); }),
            ns_per_byte(zwj.len(), iters, || { std::hint::black_box(normalize(zwj, &cfg)); }),
            ns_per_byte(spaced.len(), iters, || { std::hint::black_box(normalize(&spaced, &cfg)); }),
            ns_per_byte(stretched.len(), iters, || { std::hint::black_box(normalize(&stretched, &cfg)); }),
            ns_per_byte(pct.len(), iters, || { std::hint::black_box(normalize(&pct, &cfg)); }),
        );
    }

    println!("\n== 2. rule graph: hit-amplification (repeat a trigger token) ==");
    let g = baseline_graph();
    let mut sc = ScanScratch::new(&g);
    for &n in &sizes {
        let clean = "the quarterly report looks fine. ".repeat(n / 33 + 1);
        let flood = "ignore ".repeat(n / 7 + 1);
        // triggers everywhere, the required context token exactly once, far away
        let mut split = "ignore ".repeat(n / 7 + 1);
        split.push_str(" previous instructions");
        let iters = if n > 100_000 { 3 } else { 100 };
        println!(
            "  n={:>9}  clean={:>9.1}us  trigger_flood={:>9.1}us  flood+ctx={:>9.1}us   (hits={})",
            n,
            total_us(iters, || {
                std::hint::black_box(g.evaluate(&clean, &mut sc));
            }),
            total_us(iters, || {
                std::hint::black_box(g.evaluate(&flood, &mut sc));
            }),
            total_us(iters, || {
                std::hint::black_box(g.evaluate(&split, &mut sc));
            }),
            sc.last_hit_count(),
        );
    }

    println!("\n== 3. SecurityEngine::sanitize scaling (no size guard today) ==");
    let eng = SecurityEngine::without_policy(vec![], None);
    for &n in &[1_024usize, 8_192, 32_768, 131_072] {
        // many distinct PII items -> many sanitize passes, each O(N)
        let unit = "card 4532-0150-0000-0007 ";
        let s = unit.repeat(n / unit.len() + 1);
        println!(
            "  n={:>9}  sanitize={:>12.1}us",
            s.len(),
            total_us(1, || {
                std::hint::black_box(eng.sanitize(&s));
            })
        );
    }

    println!("\n== 4. end-to-end TieredEngine ==");
    let te = TieredEngine::with_baseline();
    for &n in &[64usize, 1_024, 16_384, 262_144] {
        let clean = "the quarterly report looks fine. ".repeat(n / 33 + 1);
        let clean = &clean[..n.min(clean.len())];
        let iters = if n > 100_000 { 20 } else { 2000 };
        println!(
            "  n={:>9}  clean_inspect={:>9.3}us",
            n,
            total_us(iters, || {
                std::hint::black_box(te.inspect_owned(clean));
            })
        );
    }

    println!("\n== 5. scratch high-water retention ==");
    let mut sc2 = ScanScratch::new(&g);
    let small = "the quarterly report looks fine.";
    g.evaluate(small, &mut sc2);
    println!(
        "  after small scan : hits={:>7}  retained={:>9} bytes",
        sc2.last_hit_count(),
        sc2.retained_bytes()
    );
    let flood = "ignore ".repeat(300_000);
    g.evaluate(&flood, &mut sc2);
    println!(
        "  after flood scan : hits={:>7}  retained={:>9} bytes",
        sc2.last_hit_count(),
        sc2.retained_bytes()
    );
    g.evaluate(small, &mut sc2);
    println!(
        "  after small again: hits={:>7}  retained={:>9} bytes  <- released",
        sc2.last_hit_count(),
        sc2.retained_bytes()
    );
}
