//! Focused: cost of normalize() on clean prose, which is the only thing the
//! folded separator gate can have regressed.
use edgeguard::deobfuscate::{normalize, NormalizerConfig};
use edgeguard::tier::TieredEngine;
use std::time::Instant;

fn best<F: FnMut()>(rounds: u32, iters: u32, mut f: F) -> f64 {
    for _ in 0..iters.min(5_000) {
        f();
    }
    let mut b = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        b = b.min(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    b
}

fn main() {
    let cfg = NormalizerConfig::injection();
    for &n in &[256usize, 1024, 16_384, 262_144] {
        let unit = "the quarterly report looks fine and margins held steady. ";
        let s = unit.repeat(n / unit.len() + 1);
        let s = &s[..n];
        let iters: u32 = if n > 100_000 { 200 } else { 20_000 };
        for _ in 0..iters.min(5_000) {
            std::hint::black_box(normalize(s, &cfg));
        }
        let mut best = f64::MAX;
        for _ in 0..12 {
            let t = Instant::now();
            for _ in 0..iters {
                std::hint::black_box(normalize(s, &cfg));
            }
            best = best.min(t.elapsed().as_nanos() as f64 / iters as f64);
        }
        println!(
            "  n={:>7}  normalize={:>9.1}ns  ({:.4} ns/byte)",
            n,
            best,
            best / n as f64
        );
    }

    println!("\n  end-to-end TieredEngine::inspect_owned, clean prose:");
    let engine = TieredEngine::with_baseline();
    for &n in &[64usize, 256, 1024, 16_384] {
        let unit = "the quarterly report looks fine and margins held steady. ";
        let s = unit.repeat(n / unit.len() + 1);
        let s = &s[..n];
        let iters: u32 = if n > 8_000 { 20_000 } else { 200_000 };
        let ns = best(12, iters, || {
            std::hint::black_box(engine.inspect_owned(s));
        });
        println!(
            "  n={:>7}  inspect={:>9.3}us  ({:.4} ns/byte)",
            n,
            ns / 1000.0,
            ns / n as f64
        );
    }
}
