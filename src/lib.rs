use aho_corasick::{AhoCorasick, MatchKind};
use unicode_normalization::UnicodeNormalization;

#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::PyDict;

pub struct SecurityEngine {
    ac: AhoCorasick,
    custom_ac: Option<AhoCorasick>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub is_safe: bool,
    pub violation_code: u32,
    pub reason: String,
    pub matched_pattern: String,
}

impl Default for SecurityEngine {
    fn default() -> Self {
        Self::new(vec![])
    }
}

impl SecurityEngine {
    pub fn new(custom_patterns: Vec<String>) -> Self {
        let base_patterns = vec![
            "ignore previous instructions",
            "system prompt",
            "jailbreak",
            "bypass",
            "dan mode",
            "developer mode",
            "override security",
            "reveal prompt",
            "disregard instructions",
        ];

        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&base_patterns)
            .unwrap();

        let custom_ac = if !custom_patterns.is_empty() {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&custom_patterns)
                    .unwrap(),
            )
        } else {
            None
        };

        SecurityEngine { ac, custom_ac }
    }

    fn decode_url(input: &str) -> String {
        let mut result = Vec::new();
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(hex_val) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                    result.push(hex_val);
                    i += 3;
                    continue;
                }
            }
            result.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&result).to_string()
    }

    fn clean_unicode(input: &str) -> (String, bool) {
        let mut had_bidi = false;
        let cleaned: String = input
            .nfkc()
            .filter(|c| {
                if matches!(*c, '\u{202A}'..='\u{202E}') {
                    had_bidi = true;
                }
                !matches!(
                    *c,
                    '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\0'
                )
            })
            .collect();
        (cleaned, had_bidi)
    }

    fn normalize_homoglyphs_and_leetspeak(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                'а' | 'А' | '@' | '4' => 'a',
                'в' | 'В' | '8' => 'b',
                'с' | 'С' => 'c',
                'е' | 'Е' | '3' => 'e',
                'і' | 'І' | '1' | '!' | '|' => 'i',
                'ј' | 'Ј' => 'j',
                'к' | 'К' => 'k',
                'о' | 'О' | '0' => 'o',
                'р' | 'Р' => 'p',
                'ѕ' | 'Ѕ' | '5' | '$' => 's',
                'т' | 'Т' | '7' => 't',
                'у' | 'У' => 'y',
                'х' | 'Х' => 'x',
                _ => c.to_ascii_lowercase(),
            })
            .collect()
    }

    fn squeeze_and_strip(input: &str) -> String {
        let mut squeezed = String::with_capacity(input.len());
        let mut last_char = None;
        for c in input.chars() {
            if c.is_alphanumeric() {
                if Some(c) != last_char {
                    squeezed.push(c);
                    last_char = Some(c);
                }
            }
        }
        squeezed
    }

    fn check_luhn(number: &str) -> bool {
        let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }

        let mut sum = 0;
        let mut alternate = false;
        for &d in digits.iter().rev() {
            let mut val = d;
            if alternate {
                val *= 2;
                if val > 9 {
                    val -= 9;
                }
            }
            sum += val;
            alternate = !alternate;
        }
        sum % 10 == 0
    }

    fn has_contiguous_luhn(prompt: &str) -> bool {
        for token in prompt.split(|c: char| c.is_whitespace() || c == ',' || c == '/' || c == ':' || c == ';') {
            let clean_digits: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
            let is_only_digit_delims = token.chars().all(|c| c.is_ascii_digit() || c == '-' || c == ' ');
            
            if is_only_digit_delims && clean_digits.len() >= 13 && clean_digits.len() <= 19 {
                if Self::check_luhn(&clean_digits) {
                    return true;
                }
            }
        }
        false
    }

    fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut freq = [0usize; 256];
        for &b in s.as_bytes() {
            freq[b as usize] += 1;
        }
        let len = s.len() as f64;
        let mut entropy = 0.0;
        for &f in freq.iter() {
            if f > 0 {
                let p = f as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    pub fn scan(&self, prompt: &str) -> ScanResult {
        let decoded = Self::decode_url(prompt);
        let (cleaned, had_bidi) = Self::clean_unicode(&decoded);
        let normalized = Self::normalize_homoglyphs_and_leetspeak(&cleaned);
        let normalized_spaces: String = normalized.chars().map(|c| if c == '_' || c == '-' || c == '.' { ' ' } else { c }).collect();
        let squeezed = Self::squeeze_and_strip(&normalized);

        let reversed_normalized: Option<String> = if had_bidi {
            Some(normalized.chars().rev().collect())
        } else {
            None
        };
        let reversed_words: Option<String> = if had_bidi {
            Some(
                normalized
                    .split_whitespace()
                    .map(|w| w.chars().rev().collect::<String>())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        } else {
            None
        };

        // 1. Custom Security Patterns
        if let Some(ref custom_ac) = self.custom_ac {
            if let Some(mat) = custom_ac.find(&cleaned)
                .or_else(|| custom_ac.find(&normalized))
                .or_else(|| custom_ac.find(&normalized_spaces))
                .or_else(|| reversed_normalized.as_ref().and_then(|rev| custom_ac.find(rev)))
                .or_else(|| reversed_words.as_ref().and_then(|rev| custom_ac.find(rev)))
            {
                return ScanResult {
                    is_safe: false,
                    violation_code: 103,
                    reason: "Custom Security Pattern Detected".to_string(),
                    matched_pattern: prompt[mat.start()..mat.end().min(prompt.len())].to_string(),
                };
            }
        }

        // 2. Base Prompt Injection Patterns
        if let Some(mat) = self.ac.find(&cleaned)
            .or_else(|| self.ac.find(&normalized))
            .or_else(|| self.ac.find(&normalized_spaces))
            .or_else(|| reversed_normalized.as_ref().and_then(|rev| self.ac.find(rev)))
            .or_else(|| reversed_words.as_ref().and_then(|rev| self.ac.find(rev)))
        {
            return ScanResult {
                is_safe: false,
                violation_code: 101,
                reason: "Prompt Injection Detected".to_string(),
                matched_pattern: prompt[mat.start()..mat.end().min(prompt.len())].to_string(),
            };
        }

        // 3. Squeezed Obfuscated Patterns
        let collapsed_targets = [
            "ignorepreviousinstructions",
            "systemprompt",
            "jailbreak",
            "danmode",
            "overridesecurity",
            "overrideinstructions",
            "disregardinstructions",
        ];
        for target in &collapsed_targets {
            if squeezed.contains(target) {
                return ScanResult {
                    is_safe: false,
                    violation_code: 101,
                    reason: "Obfuscated Prompt Injection Detected".to_string(),
                    matched_pattern: target.to_string(),
                };
            }
        }

        // 4. PII Contiguous Luhn Check
        if Self::has_contiguous_luhn(prompt) {
            return ScanResult {
                is_safe: false,
                violation_code: 301,
                reason: "PII Detected - Valid Credit Card Number".to_string(),
                matched_pattern: "CREDIT_CARD_NUM".to_string(),
            };
        }

        // 5. Entropy Detection (Skip pure digits)
        for token in prompt.split_whitespace() {
            let clean_token = token.trim_matches(|c: char| !c.is_alphanumeric());
            let is_pure_digits = !clean_token.is_empty() && clean_token.chars().all(|c| c.is_ascii_digit());
            
            if !is_pure_digits && clean_token.len() >= 24 && Self::calculate_entropy(clean_token) > 4.5 {
                return ScanResult {
                    is_safe: false,
                    violation_code: 201,
                    reason: "High Entropy Encrypted Payload Detected".to_string(),
                    matched_pattern: clean_token.to_string(),
                };
            }
        }

        ScanResult {
            is_safe: true,
            violation_code: 0,
            reason: "Safe".to_string(),
            matched_pattern: String::new(),
        }
    }

    pub fn sanitize(&self, prompt: &str) -> String {
        let (cleaned, _) = Self::clean_unicode(prompt);
        let digits_only: String = cleaned.chars().filter(|c| c.is_ascii_digit()).collect();
        
        if (digits_only.len() == 15 || digits_only.len() == 16) && Self::check_luhn(&digits_only) {
            let mut masked = String::new();
            let mut digit_count = 0;
            let total_digits = digits_only.len();
            
            for c in cleaned.chars() {
                if c.is_ascii_digit() {
                    digit_count += 1;
                    if digit_count > 4 && digit_count <= total_digits - 4 {
                        masked.push('*');
                    } else {
                        masked.push(c);
                    }
                } else {
                    masked.push(c);
                }
            }
            masked
        } else {
            cleaned
        }
    }
}

#[cfg(feature = "python")]
#[pyclass(name = "EdgeGuard")]
pub struct PyEdgeGuard {
    inner: SecurityEngine,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyEdgeGuard {
    #[new]
    #[pyo3(signature = (custom_patterns=None))]
    fn new(custom_patterns: Option<Vec<String>>) -> Self {
        PyEdgeGuard {
            inner: SecurityEngine::new(custom_patterns.unwrap_or_default()),
        }
    }

    fn scan<'py>(&self, py: Python<'py>, prompt: &str) -> PyResult<Bound<'py, PyDict>> {
        let res = self.inner.scan(prompt);
        let dict = PyDict::new_bound(py);
        dict.set_item("is_safe", res.is_safe)?;
        dict.set_item("violation_code", res.violation_code)?;
        dict.set_item("reason", res.reason)?;
        dict.set_item("matched_pattern", res.matched_pattern)?;
        Ok(dict)
    }

    fn sanitize(&self, prompt: &str) -> String {
        self.inner.sanitize(prompt)
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn edgeguard(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEdgeGuard>()?;
    Ok(())
}