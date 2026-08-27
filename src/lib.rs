use std::ffi::CStr;
use std::fs::File;
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;
use std::sync::{OnceLock, RwLock};
use regex::Regex;
use serde::Deserialize;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

#[repr(C)]
pub struct ScanResult {
    pub is_safe: bool,
    pub violation_code: c_int,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleConfig {
    pub id: i32,
    pub name: String,
    pub enabled: bool,
    pub pattern: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    pub version: String,
    pub rules: Vec<RuleConfig>,
}

pub struct CompiledRule {
    pub id: i32,
    pub regex: Regex,
}

pub struct CompiledPolicy {
    pub rules: Vec<CompiledRule>,
}

static POLICY_STORE: OnceLock<RwLock<CompiledPolicy>> = OnceLock::new();
static BASE64_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_default_policy() -> CompiledPolicy {
    let default_rules = vec![
        (4, r"(?i)(ignore previous instructions|system override|jailbreak|disregard all prior)"),
        (3, r"(?i)(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})"),
        (2, r"\b(?:\d[ -]*?){13,16}\b"),
        (1, r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    ];

    let rules = default_rules
        .into_iter()
        .filter_map(|(id, pat)| {
            Regex::new(pat).ok().map(|regex| CompiledRule { id, regex })
        })
        .collect();

    CompiledPolicy { rules }
}

fn get_policy_store() -> &'static RwLock<CompiledPolicy> {
    POLICY_STORE.get_or_init(|| RwLock::new(get_default_policy()))
}

fn calculate_shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }

    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn check_high_entropy_secrets(text: &str) -> bool {
    // Check tokens longer than 20 characters for high Shannon entropy (> 4.5 bits)
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric());
        if clean.len() >= 24 && calculate_shannon_entropy(clean) >= 4.4 {
            return true;
        }
    }
    false
}

fn check_base64_obfuscation(text: &str, policy: &CompiledPolicy) -> Option<c_int> {
    let b64_re = BASE64_REGEX.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9+/]{24,}={0,2}").unwrap()
    });

    for mat in b64_re.find_iter(text) {
        let candidate = mat.as_str();
        if let Ok(decoded_bytes) = BASE64_STANDARD.decode(candidate) {
            if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                for rule in &policy.rules {
                    if rule.regex.is_match(decoded_str) {
                        return Some(6); // Base64 Encoded Violation
                    }
                }
            }
        }
    }
    None
}

fn evaluate_buffer(text: &str) -> (bool, c_int) {
    let store = get_policy_store();
    let policy = match store.read() {
        Ok(guard) => guard,
        Err(_) => return (false, -1),
    };

    // 1. Direct Regex scan
    for rule in &policy.rules {
        if rule.regex.is_match(text) {
            return (false, rule.id);
        }
    }

    // 2. Base64 Payload scan (Obfuscation Detection)
    if let Some(violation_code) = check_base64_obfuscation(text, &policy) {
        return (false, violation_code);
    }

    // 3. Shannon Entropy scan (Unknown API keys / Raw Secrets)
    if check_high_entropy_secrets(text) {
        return (false, 5); // Code 5: High-Entropy Secret
    }

    (true, 0)
}

// ----------------------------------------------------
// Policy Management API
// ----------------------------------------------------

#[no_mangle]
pub extern "C" fn edgeguard_load_policy_file(file_path: *const c_char) -> c_int {
    let result = catch_unwind(|| {
        if file_path.is_null() {
            return -1;
        }

        let c_str = unsafe { CStr::from_ptr(file_path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let file = match File::open(path_str) {
            Ok(f) => f,
            Err(_) => return -2,
        };

        let config: PolicyConfig = match serde_yaml::from_reader(file) {
            Ok(c) => c,
            Err(_) => return -3,
        };

        let mut new_rules = Vec::new();
        for r in config.rules {
            if r.enabled {
                if let Ok(compiled) = Regex::new(&r.pattern) {
                    new_rules.push(CompiledRule {
                        id: r.id,
                        regex: compiled,
                    });
                } else {
                    return -4;
                }
            }
        }

        let store = get_policy_store();
        if let Ok(mut write_guard) = store.write() {
            *write_guard = CompiledPolicy { rules: new_rules };
            0
        } else {
            -5
        }
    });

    result.unwrap_or(-1)
}

// ----------------------------------------------------
// One-Shot API
// ----------------------------------------------------

#[no_mangle]
pub extern "C" fn scan_prompt_safe(prompt: *const c_char) -> ScanResult {
    let result = catch_unwind(|| {
        if prompt.is_null() {
            return ScanResult { is_safe: false, violation_code: -1 };
        }

        let c_str = unsafe { CStr::from_ptr(prompt) };
        let str_slice = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return ScanResult { is_safe: false, violation_code: -1 },
        };

        let (is_safe, violation_code) = evaluate_buffer(str_slice);
        ScanResult { is_safe, violation_code }
    });

    result.unwrap_or(ScanResult { is_safe: false, violation_code: -1 })
}

// ----------------------------------------------------
// Token Streaming Engine
// ----------------------------------------------------

pub struct StreamScanner {
    buffer: String,
    max_window_chars: usize,
}

impl StreamScanner {
    pub fn new(max_window_chars: usize) -> Self {
        Self {
            buffer: String::with_capacity(max_window_chars * 2),
            max_window_chars,
        }
    }

    pub fn push_token(&mut self, token: &str) -> (bool, c_int) {
        self.buffer.push_str(token);

        let (is_safe, code) = evaluate_buffer(&self.buffer);
        if !is_safe {
            return (false, code);
        }

        if self.buffer.len() > self.max_window_chars {
            let drain_count = self.buffer.len() - self.max_window_chars;
            if let Some((idx, _)) = self.buffer.char_indices().find(|&(i, _)| i >= drain_count) {
                self.buffer.drain(..idx);
            }
        }

        (true, 0)
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
    }
}

#[no_mangle]
pub extern "C" fn stream_scanner_create(max_window_chars: usize) -> *mut StreamScanner {
    let result = catch_unwind(|| {
        let scanner = Box::new(StreamScanner::new(if max_window_chars == 0 { 256 } else { max_window_chars }));
        Box::into_raw(scanner)
    });
    result.unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn stream_scanner_feed(scanner_ptr: *mut StreamScanner, token_ptr: *const c_char) -> ScanResult {
    let result = catch_unwind(|| {
        if scanner_ptr.is_null() || token_ptr.is_null() {
            return ScanResult { is_safe: false, violation_code: -1 };
        }

        let scanner = unsafe { &mut *scanner_ptr };
        let c_str = unsafe { CStr::from_ptr(token_ptr) };
        let token_slice = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return ScanResult { is_safe: false, violation_code: -1 },
        };

        let (is_safe, violation_code) = scanner.push_token(token_slice);
        ScanResult { is_safe, violation_code }
    });

    result.unwrap_or(ScanResult { is_safe: false, violation_code: -1 })
}

#[no_mangle]
pub extern "C" fn stream_scanner_reset(scanner_ptr: *mut StreamScanner) {
    let _ = catch_unwind(|| {
        if !scanner_ptr.is_null() {
            let scanner = unsafe { &mut *scanner_ptr };
            scanner.reset();
        }
    });
}

#[no_mangle]
pub extern "C" fn stream_scanner_free(scanner_ptr: *mut StreamScanner) {
    let _ = catch_unwind(|| {
        if !scanner_ptr.is_null() {
            unsafe {
                drop(Box::from_raw(scanner_ptr));
            }
        }
    });
}