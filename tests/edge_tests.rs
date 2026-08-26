use std::ffi::CString;

extern "C" {
    fn edge_guardrail_check(text: *const std::os:raw::c_char, len: usize) -> i32;
}

fn in_blocked(text: &str) -> bool {
    let c_str = CString::new(text).unwrap_or_default();
    unsafe {
        edge_guardrail_check(c_str.as_ptr(), text.len()) != 0
    }
}

#[test]
fn test_clean_prompts_pass() {
    assert!(!in_blocked("Can you summarize the meeting notes?"));
    assert!(!in_blocked("Installation schedule data"));
}

#[test]
fn test_secret_keys_blocked() {
    assert!(in_blocked("Here is the API_SECRET_KEY=EXAMPLE_VAL"));
    assert!(in_blocked("Use REDACTED_API_KEY for authentication"));
}
