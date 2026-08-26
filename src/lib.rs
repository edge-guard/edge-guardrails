use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref RE_EMAIL: Regex = Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap();
    static ref RE_CREDIT_CARD: Regex = Regex::new(r"\b(?:\d{4}[ -]?){3}\d{4}\b").unwrap();
    static ref RE_API_KEY: Regex = Regex::new(r"\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b").unwrap();
    static ref RE_INJECTION: Regex = Regex::new(r"(?i)\b(ignore previous instructions|system prompt|bypass rules)\b").unwrap();
}

#[repr(C)]
pub struct ScanResult {
    pub is_safe: bool,
    pub violation_code: i32, // 0 = Safe, 1 = Email, 2 = Credit Card, 3 = API Key, 4 = Prompt Injection, -1 = Error/Panic
}

#[no_mangle]
pub extern "C" fn scan_prompt_safe(input: *const c_char) -> ScanResult {
    let result = catch_unwind(|| {
        if input.is_null() {
            return ScanResult { is_safe: false, violation_code: -1 };
        }

        let c_str = unsafe { CStr::from_ptr(input) };
        let text = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return ScanResult { is_safe: false, violation_code: -1 },
        };

        if RE_API_KEY.is_match(text) {
            return ScanResult { is_safe: false, violation_code: 3 };
        }
        if RE_INJECTION.is_match(text) {
            return ScanResult { is_safe: false, violation_code: 4 };
        }
        if RE_CREDIT_CARD.is_match(text) {
            return ScanResult { is_safe: false, violation_code: 2 };
        }
        if RE_EMAIL.is_match(text) {
            return ScanResult { is_safe: false, violation_code: 1 };
        }

        ScanResult { is_safe: true, violation_code: 0 }
    });

    match result {
        Ok(res) => res,
        Err(_) => ScanResult { is_safe: false, violation_code: -1 },
    }
}