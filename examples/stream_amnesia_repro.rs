//! Side by side: the old rolling-window logic (which forgets) against the
//! latching `StreamScanner` that replaced it.
use edgeguard::stream::StreamScanner;
use edgeguard::SecurityEngine;
use std::sync::Arc;

fn main() {
    let eng = SecurityEngine::new(vec![], None, None);
    let window_size = 32usize;
    let mut window = String::new();

    let stream = [
        "Here ",
        "is ",
        "your ",
        "key: ",
        "AKIA",
        "IOSFODNN7EXAMPLE",
        ". ",
        "Now ",
        "some ",
        "perfectly ",
        "ordinary ",
        "filler ",
        "text ",
        "that ",
        "pushes ",
        "the ",
        "secret ",
        "out ",
        "of ",
        "the ",
        "window ",
        "entirely ",
        "and ",
        "keeps ",
        "going ",
        "for ",
        "a ",
        "while.",
    ];

    println!(
        "{:<4} {:<22} {:>8}  {}",
        "tok", "token", "verdict", "window"
    );
    let mut ever_flagged = false;
    let mut last_safe = true;
    for (i, tok) in stream.iter().enumerate() {
        window.push_str(tok);
        let n = window.chars().count();
        if n > window_size {
            let excess = n - window_size;
            window = window.chars().skip(excess).collect();
        }
        let res = eng.scan(&window);
        if !res.is_safe {
            ever_flagged = true;
        }
        last_safe = res.is_safe;
        if i < 7 || i > stream.len() - 4 || !res.is_safe {
            println!(
                "{:<4} {:<22} {:>8}  {:?}",
                i,
                tok,
                if res.is_safe { "SAFE" } else { "BLOCK" },
                window
            );
        }
    }
    println!();
    println!("OLD (rolling window only)");
    println!(
        "  a secret WAS emitted and detected mid-stream : {}",
        ever_flagged
    );
    println!(
        "  final verdict the caller gates on            : {}",
        if last_safe {
            "SAFE  <-- the stream forgot"
        } else {
            "BLOCK"
        }
    );

    // Same stream, same window size, through the latching scanner.
    let mut s = StreamScanner::new(
        Arc::new(SecurityEngine::new(vec![], None, None)),
        window_size,
    );
    let mut tripped_at = None;
    let mut last = None;
    for (i, tok) in stream.iter().enumerate() {
        let v = s.feed_token(tok);
        if v.just_tripped {
            tripped_at = Some((i, v.violation_code));
        }
        last = Some(v);
    }
    let v = last.unwrap();
    println!();
    println!("NEW (latching StreamScanner)");
    println!(
        "  tripped at token                            : {:?}",
        tripped_at
    );
    println!(
        "  final verdict the caller gates on           : {}",
        if v.is_safe {
            "SAFE"
        } else {
            "BLOCK <-- latched"
        }
    );
    println!(
        "  verdict held by the latch, not the window   : {}",
        v.latched
    );
    println!(
        "  window now                                  : {:?}",
        s.window()
    );
    println!(
        "  distinct violation codes seen               : {:?}",
        s.codes_seen()
    );
}
