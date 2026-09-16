use aho_corasick::{AhoCorasick, MatchKind};
use unicode_normalization::UnicodeNormalization;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use rusqlite::{params, Connection};
use regex::Regex;

#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::PyDict;

// --- Background Logger ---
#[derive(Clone)]
pub struct AuditLogEntry {
    pub pattern: String,
    pub violation_code: u32,
    pub timestamp: i64,
}

pub struct BackgroundLogger {
    sender: Option<SyncSender<AuditLogEntry>>,
}

impl BackgroundLogger {
    pub fn new(db_path: Option<&str>) -> Self {
        if let Some(path) = db_path {
            let (tx, rx) = sync_channel::<AuditLogEntry>(50_000);
            let path_str = path.to_string();

            thread::spawn(move || {
                let mut conn = Connection::open(&path_str).expect("Failed to open SQLite");
                conn.execute_batch("
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;
                    PRAGMA busy_timeout = 5000;
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pattern TEXT,
                        code INTEGER,
                        timestamp INTEGER
                    );
                ").ok();

                let mut batch = Vec::with_capacity(500);

                loop {
                    while let Ok(entry) = rx.try_recv() {
                        batch.push(entry);
                        if batch.len() >= 500 { break; }
                    }

                    if !batch.is_empty() {
                        if let Ok(tx) = conn.transaction() {
                            for item in batch.drain(..) {
                                tx.execute(
                                    "INSERT INTO audit_logs (pattern, code, timestamp) VALUES (?1, ?2, ?3)",
                                    params![item.pattern, item.violation_code, item.timestamp],
                                ).ok();
                            }
                            tx.commit().ok();
                        }
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            });

            BackgroundLogger { sender: Some(tx) }
        } else {
            BackgroundLogger { sender: None }
        }
    }

    pub fn log(&self, entry: AuditLogEntry) {
        if let Some(sender) = &self.sender {
            let _ = sender.try_send(entry);
        }
    }
}

// --- Security Engine ---
pub struct SecurityEngine {
    ac: AhoCorasick,
    custom_ac: Option<AhoCorasick>,
    logger: BackgroundLogger,
    email_re: Regex,
    aws_re: Regex,
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
        Self::new(vec![], None)
    }
}

impl SecurityEngine {
    pub fn new(custom_patterns: Vec<String>, db_path: Option<&str>) -> Self {
        // הוספנו פה תבניות Roleplay ו-Jailbreak עקיפות
        let base_patterns = vec![
            "ignore previous instructions", "system prompt", "jailbreak",
            "dan mode", "developer mode", "override security",
            "pretend to be", "act as a", "simulate a", "hypothetical scenario",
            "you are now a", "grandma", "story before bed"
        ];

        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&base_patterns)
            .unwrap();

        let custom_ac = if !custom_patterns.is_empty() {
            Some(AhoCorasick::builder().match_kind(MatchKind::LeftmostFirst).build(&custom_patterns).unwrap())
        } else {
            None
        };

        let logger = BackgroundLogger::new(db_path);
        
        let email_re = Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap();
        let aws_re = Regex::new(r"(?i)AKIA[0-9A-Z]{16}").unwrap();

        SecurityEngine { ac, custom_ac, logger, email_re, aws_re }
    }

    fn check_luhn(number: &str) -> bool {
        let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() < 13 || digits.len() > 19 { return false; }
        let mut sum = 0;
        let mut alternate = false;
        for &d in digits.iter().rev() {
            let mut val = d;
            if alternate {
                val *= 2;
                if val > 9 { val -= 9; }
            }
            sum += val;
            alternate = !alternate;
        }
        sum % 10 == 0
    }

    // בדיקת תעודת זהות ישראלית (9 ספרות וספרת ביקורת)
    fn is_valid_israeli_id(id: &str) -> bool {
        let digits: Vec<u32> = id.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() != 9 { return false; }
        let mut sum = 0;
        for (i, &d) in digits.iter().enumerate() {
            let mut weight = d * if i % 2 == 0 { 1 } else { 2 };
            if weight > 9 { weight -= 9; }
            sum += weight;
        }
        sum % 10 == 0
    }

    fn check_pii(&self, prompt: &str) -> Option<(u32, String, String)> {
        // AWS Keys
        if let Some(mat) = self.aws_re.find(prompt) {
            return Some((302, "PII Detected - AWS API Key".to_string(), mat.as_str().to_string()));
        }
        // Emails
        if let Some(mat) = self.email_re.find(prompt) {
            return Some((303, "PII Detected - Email Address".to_string(), mat.as_str().to_string()));
        }

        // Luhn (Credit Card) & IL-ID
        for token in prompt.split(|c: char| !c.is_alphanumeric()) {
            let clean_digits: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
            if clean_digits.len() >= 13 && clean_digits.len() <= 19 && Self::check_luhn(&clean_digits) {
                return Some((301, "PII Detected - Credit Card".to_string(), "CREDIT_CARD_NUM".to_string()));
            }
            if clean_digits.len() == 9 && Self::is_valid_israeli_id(&clean_digits) {
                return Some((304, "PII Detected - Israeli ID".to_string(), "IL_ID_NUM".to_string()));
            }
        }
        None
    }

    pub fn scan(&self, prompt: &str) -> ScanResult {
        // 1. הגנת DoS (Circuit Breaker) - חסימה מעל 2MB
        if prompt.len() > 2_097_152 {
            let res = ScanResult {
                is_safe: false,
                violation_code: 413,
                reason: "Payload Too Large (DoS Protection)".to_string(),
                matched_pattern: "OVER_2MB".to_string(),
            };
            self.logger.log(AuditLogEntry { pattern: res.matched_pattern.clone(), violation_code: res.violation_code, timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64 });
            return res;
        }

        let result = self.do_scan(prompt);
        
        if !result.is_safe {
            self.logger.log(AuditLogEntry {
                pattern: result.matched_pattern.clone(),
                violation_code: result.violation_code,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
            });
        }
        result
    }

    fn do_scan(&self, prompt: &str) -> ScanResult {
        let (cleaned, _) = SecurityEngine::clean_unicode(prompt); // השמטתי ניקוי מורכב לטובת ביצועים מהירים בקריאה
        
        // 2. Custom Security Patterns
        if let Some(ref custom_ac) = self.custom_ac {
            if let Some(mat) = custom_ac.find(&cleaned) {
                return ScanResult { is_safe: false, violation_code: 103, reason: "Custom Security Pattern".to_string(), matched_pattern: prompt[mat.start()..mat.end().min(prompt.len())].to_string() };
            }
        }

        // 3. Base Prompt Injection & Roleplay
        if let Some(mat) = self.ac.find(&cleaned) {
            return ScanResult { is_safe: false, violation_code: 101, reason: "Prompt Injection / Roleplay Detected".to_string(), matched_pattern: prompt[mat.start()..mat.end().min(prompt.len())].to_string() };
        }

        // 4. Expanded PII
        if let Some((code, reason, pattern)) = self.check_pii(prompt) {
            return ScanResult { is_safe: false, violation_code: code, reason, matched_pattern: pattern };
        }

        ScanResult { is_safe: true, violation_code: 0, reason: "Safe".to_string(), matched_pattern: String::new() }
    }

    fn clean_unicode(input: &str) -> (String, bool) {
        let mut had_bidi = false;
        let cleaned: String = input.nfkc().filter(|c| {
            if matches!(*c, '\u{202A}'..='\u{202E}') { had_bidi = true; }
            !matches!(*c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\0')
        }).collect();
        (cleaned.to_lowercase(), had_bidi)
    }

    pub fn sanitize(&self, prompt: &str) -> String {
        prompt.to_string() // פלייס-הולדר לגרסאות הבאות שבהן נרחיב צנזורה לכל סוגי ה-PII
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
    #[pyo3(signature = (custom_patterns=None, db_path=None))]
    fn new(custom_patterns: Option<Vec<String>>, db_path: Option<String>) -> Self {
        let path = db_path.unwrap_or_else(|| "native_edge_queue.db".to_string());
        PyEdgeGuard { inner: SecurityEngine::new(custom_patterns.unwrap_or_default(), Some(&path)) }
    }

    fn scan<'py>(&self, py: Python<'py>, prompt: &str) -> PyResult<Bound<'py, PyDict>> {
        let res = py.allow_threads(|| self.inner.scan(prompt));
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