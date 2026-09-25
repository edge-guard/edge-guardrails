//! Append-only raw result storage.
//!
//! Pack §7 requires raw decisions and timing records to be preserved. "Raw"
//! here means: one JSON object per line, written once, never rewritten. The
//! writer opens in append mode and refuses to truncate, so a second run adds
//! to the record rather than replacing it - which is what makes a second look
//! at the holdout *visible* (Pack §6.7, holdout policy rule 3).

use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub struct RawWriter {
    path: PathBuf,
    out: BufWriter<std::fs::File>,
    written: u64,
}

#[derive(Debug)]
pub enum WriteError {
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::Io(e) => write!(f, "io: {e}"),
            WriteError::Serde(e) => write!(f, "serialize: {e}"),
        }
    }
}

impl From<std::io::Error> for WriteError {
    fn from(e: std::io::Error) -> Self {
        WriteError::Io(e)
    }
}
impl From<serde_json::Error> for WriteError {
    fn from(e: serde_json::Error) -> Self {
        WriteError::Serde(e)
    }
}

impl RawWriter {
    /// Open for append. Never truncates: `create(true).append(true)`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WriteError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(RawWriter {
            path,
            out: BufWriter::new(f),
            written: 0,
        })
    }

    pub fn append<T: Serialize>(&mut self, record: &T) -> Result<(), WriteError> {
        let line = serde_json::to_string(record)?;
        debug_assert!(!line.contains('\n'), "JSONL record must be one line");
        writeln!(self.out, "{line}")?;
        self.written += 1;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), WriteError> {
        self.out.flush()?;
        Ok(())
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct R {
        id: u32,
    }

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("eg_exp_{}_{}.jsonl", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn records_are_appended_one_per_line() {
        let p = tmp("append");
        {
            let mut w = RawWriter::open(&p).unwrap();
            w.append(&R { id: 1 }).unwrap();
            w.append(&R { id: 2 }).unwrap();
            w.flush().unwrap();
            assert_eq!(w.written(), 2);
        }
        let s = std::fs::read_to_string(&p).unwrap();
        assert_eq!(s.lines().count(), 2);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn reopening_appends_rather_than_truncating_so_a_second_run_is_visible() {
        let p = tmp("second_look");
        {
            let mut w = RawWriter::open(&p).unwrap();
            w.append(&R { id: 1 }).unwrap();
            w.flush().unwrap();
        }
        {
            let mut w = RawWriter::open(&p).unwrap();
            w.append(&R { id: 2 }).unwrap();
            w.flush().unwrap();
        }
        let s = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            s.lines().count(),
            2,
            "a re-open must not erase the first run's record"
        );
        let _ = std::fs::remove_file(&p);
    }
}
