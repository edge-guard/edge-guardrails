//! Local-only work queue for the slow path.
//!
//! # What this is for
//!
//! Tier 1 triages in microseconds. When it cannot decide - a `Flag` rule
//! matched, obfuscation layers stacked, or a decoded lane looked wrong - the
//! request is *grey*, and answering it needs a semantic model that costs
//! roughly 10,000x a Tier 1 scan. The Fast-Path/Slow-Path split defers that
//! work instead of paying for it inline: the router returns immediately and
//! the prompt is parked here for a local worker to score out of band.
//!
//! # Why this is NOT [`crate::audit_queue`]
//!
//! It is the obvious reuse and it would be a serious mistake.
//!
//! `AuditQueue` exists to get verdicts **off the device** to the control
//! plane, and its record type is built around that: "a category, never a
//! value". No prompt text can reach it, by construction, because the outbox
//! is shipped over the network.
//!
//! This queue is the exact inverse. A semantic model cannot score a category;
//! it needs the prompt itself, so **this store holds raw prompt text**, which
//! makes it the most sensitive file the SDK writes. Putting deferred work in
//! the audit outbox would place user prompts in a queue whose whole purpose
//! is transmission. That is a data incident with a migration attached, not a
//! schema change.
//!
//! So the two are kept apart, and the separation is **structural rather than
//! documentary**:
//!
//! * this store lives in its own database file with its own schema;
//! * [`DeferredQueue::open`] refuses to attach to any database that contains
//!   an `audit_outbox` table, so pointing it at the outbox fails loudly at
//!   startup instead of quietly succeeding;
//! * there is deliberately **no** `OutboxReader` analogue, no lease/ship/ack
//!   cycle and no serialization to bytes. Nothing in this module can put a
//!   row on a network;
//! * rows expire. An unscored prompt is deleted once it is older than
//!   [`DeferredConfig::ttl`] whether or not anyone got to it, because
//!   retaining user text indefinitely to maybe score it later is not a
//!   trade this SDK gets to make on an operator's behalf;
//! * [`DeferredQueue::complete`] deletes the row. The prompt exists only for
//!   as long as the work does.
//!
//! # The invariant inherited from the audit outbox
//!
//! > **`inspect()` never waits for this module, and never fails because of
//! > it.**
//!
//! Same reasoning, same mechanism: a bounded `try_send` on the producer side
//! that drops rather than blocks, all SQLite work on one owned thread, a
//! cooldown rather than a spin when the disk refuses writes, and a counter
//! for every drop. Fail-open is a decision; fail-open silently is a defect.
//!
//! Note what this means for coverage: a saturated slow path loses grey
//! prompts. That is the correct failure - the alternative is stalling the
//! fast path - but it is why [`DeferredStats::dropped`] belongs on a
//! dashboard rather than in a log nobody reads.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OpenFlags};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS deferred_work (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    prompt        TEXT    NOT NULL,
    code          INTEGER NOT NULL,
    decided_by    TEXT    NOT NULL,
    obfuscation   INTEGER NOT NULL DEFAULT 0,
    interim       TEXT    NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    claimed_until INTEGER NOT NULL DEFAULT 0
);
-- Covers the worker's only query: unclaimed, unexpired, oldest first.
CREATE INDEX IF NOT EXISTS idx_deferred_claimable
    ON deferred_work (claimed_until, id);
CREATE INDEX IF NOT EXISTS idx_deferred_expiry ON deferred_work (expires_at);
";

/// Table name owned by [`crate::audit_queue`]. Its presence in a database
/// file means this module has been pointed at the outbox.
const AUDIT_TABLE: &str = "audit_outbox";

/// Default filename for the deferred store.
///
/// Deliberately unlike the audit outbox's `native_edge_queue.db`. The open
/// guard already refuses a shared database, but a guard that fires is still
/// an outage someone has to debug at 3am - the default should make the
/// collision impossible rather than merely detectable.
pub const DEFAULT_DB_FILENAME: &str = "edgeguard_deferred.db";

/// [`DEFAULT_DB_FILENAME`] in the current directory.
pub fn default_db_path() -> PathBuf {
    PathBuf::from(DEFAULT_DB_FILENAME)
}

/// A deferred-store path that sits beside a given audit database and is
/// guaranteed to differ from it.
///
/// The realistic configuration mistake is not inventing a path - it is
/// copying the audit path into the deferred config because both are "the
/// database". This exists so the natural thing to write is also the safe
/// thing: hand it the audit path and get a sibling back.
///
/// `native_edge_queue.db` -> `native_edge_queue.deferred.db`
///
/// The result is never equal to the input, including for inputs with no
/// extension, no file name, or an existing `.deferred` stem.
pub fn beside_audit_db(audit_db: impl AsRef<Path>) -> PathBuf {
    let p = audit_db.as_ref();

    // A trailing separator means the caller named a directory, so put the
    // file inside it. Without this, "/var/lib/eg/" produced the sibling
    // "/var/lib/eg.deferred.db" while "." and ".." correctly produced a file
    // inside - `file_stem` returns None for the latter two and Some("eg")
    // for the former.
    if p.as_os_str()
        .to_str()
        .is_some_and(|s| s.ends_with(std::path::MAIN_SEPARATOR) || s.ends_with('/'))
    {
        return p.join(DEFAULT_DB_FILENAME);
    }

    let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
        // No usable file name (root, "..", a bare separator). Fall back to a
        // fixed name inside whatever directory was given rather than
        // returning something that could still collide.
        return p.join(DEFAULT_DB_FILENAME);
    };
    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("db");
    let name = format!("{stem}.deferred.{ext}");
    match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => PathBuf::from(name),
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum DeferredError {
    /// The target database belongs to the audit outbox.
    ///
    /// Refused rather than tolerated: continuing would write prompt text into
    /// a store that is shipped to the control plane.
    WouldShareAuditDb(PathBuf),
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for DeferredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeferredError::WouldShareAuditDb(p) => write!(
                f,
                "'{}' contains an `{}` table: the deferred queue holds raw prompt \
                 text and must never share a database with the audit outbox, \
                 which is shipped off the device",
                p.display(),
                AUDIT_TABLE
            ),
            DeferredError::Sqlite(e) => write!(f, "deferred queue database error: {}", e),
        }
    }
}

impl std::error::Error for DeferredError {}

impl From<rusqlite::Error> for DeferredError {
    fn from(e: rusqlite::Error) -> Self {
        DeferredError::Sqlite(e)
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// What the caller did with the request while the slow path had not answered.
///
/// Recorded per row rather than derived at scoring time, because the
/// deployment's fallback policy can change between submission and scoring,
/// and "what did we actually serve the user" is the question an incident
/// review asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interim {
    /// Served normally.
    Serve,
    /// Served, but marked for review.
    ServeAndMark,
    /// Refused up front.
    Refuse,
}

impl Interim {
    pub fn as_str(self) -> &'static str {
        match self {
            Interim::Serve => "serve",
            Interim::ServeAndMark => "serve_and_mark",
            Interim::Refuse => "refuse",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "serve" => Interim::Serve,
            "refuse" => Interim::Refuse,
            // Unknown values fall to the middle disposition rather than to
            // `Serve`: a row written by a newer version must not be read back
            // as the most permissive option available.
            _ => Interim::ServeAndMark,
        }
    }
}

/// One parked request.
#[derive(Debug, Clone)]
pub struct DeferredItem {
    pub id: i64,
    pub ts: i64,
    /// The prompt, verbatim. The reason this store exists and the reason it
    /// never leaves the device.
    pub prompt: String,
    pub code: u32,
    pub decided_by: String,
    pub obfuscation: u16,
    pub interim: Interim,
    pub attempts: u32,
}

/// Submission as it crosses the channel to the writer thread.
#[derive(Debug, Clone)]
struct Submission {
    ts: i64,
    expires_at: i64,
    prompt: String,
    code: u32,
    decided_by: String,
    obfuscation: u16,
    interim: Interim,
}

#[derive(Debug, Default)]
pub struct DeferredStats {
    pub offered: AtomicU64,
    pub persisted: AtomicU64,
    /// Channel was full. The slow path is behind; grey prompts are being lost.
    pub dropped_full: AtomicU64,
    /// No usable database this session.
    pub dropped_no_sink: AtomicU64,
    /// Refused before the channel: over `max_prompt_bytes`.
    pub dropped_oversize: AtomicU64,
    pub write_failures: AtomicU64,
    pub evicted_backlog: AtomicU64,
    pub expired: AtomicU64,
    pub degraded_periods: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DeferredSnapshot {
    pub offered: u64,
    pub persisted: u64,
    pub dropped_full: u64,
    pub dropped_no_sink: u64,
    pub dropped_oversize: u64,
    pub write_failures: u64,
    pub evicted_backlog: u64,
    pub expired: u64,
    pub degraded_periods: u64,
}

impl DeferredSnapshot {
    /// Grey prompts that were never parked, for any reason. The slow path's
    /// blind spot, and the number that says whether deferral is actually
    /// covering the traffic it claims to.
    pub fn lost(&self) -> u64 {
        self.dropped_full + self.dropped_no_sink + self.dropped_oversize + self.write_failures
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DeferredConfig {
    /// In-memory hand-off depth. Full means drop, never block.
    pub channel_depth: usize,
    /// Largest number of parked rows. Past this the oldest are evicted.
    ///
    /// Much smaller than the audit outbox's 200k: these rows carry prompt
    /// text, so the backlog is a privacy exposure as well as a disk cost, and
    /// work that is hours stale is not worth scoring anyway.
    pub max_backlog_rows: u64,
    /// How long an unscored row lives before it is deleted regardless.
    pub ttl: Duration,
    /// How often the sweeper deletes expired and evicts over-cap rows.
    pub sweep_interval: Duration,
    /// Refuse to park a prompt larger than this.
    ///
    /// Transformer cost is quadratic in sequence length and the scorer
    /// truncates to `max_seq_len` anyway, so storing a 2 MB prompt buys a few
    /// hundred tokens of signal at the price of a large block of retained
    /// user text.
    pub max_prompt_bytes: usize,
    /// How long a claimed-but-uncompleted row stays invisible.
    pub claim_timeout: Duration,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub failure_cooldown: Duration,
    pub busy_timeout: Duration,
    pub max_db_pages: Option<u32>,
}

impl Default for DeferredConfig {
    fn default() -> Self {
        Self {
            channel_depth: 10_000,
            max_backlog_rows: 20_000,
            // An hour. Long enough to absorb a restart or a backlog spike,
            // short enough that a device seized tomorrow is not carrying a
            // day of user prompts.
            ttl: Duration::from_secs(3_600),
            sweep_interval: Duration::from_secs(60),
            max_prompt_bytes: 16 * 1024,
            claim_timeout: Duration::from_secs(120),
            batch_size: 200,
            flush_interval: Duration::from_millis(50),
            failure_cooldown: Duration::from_secs(5),
            busy_timeout: Duration::from_millis(250),
            // ~64 MB. Smaller than the outbox on purpose; see max_backlog_rows.
            max_db_pages: Some(16_384),
        }
    }
}

// ---------------------------------------------------------------------------
// Producer handle
// ---------------------------------------------------------------------------

/// The handle the router's caller holds.
///
/// Deliberately submission-only. Reading parked work is
/// [`DeferredWorker`]'s job, so a component that merely defers cannot also
/// enumerate prompts.
#[derive(Debug)]
pub struct DeferredQueue {
    tx: SyncSender<Submission>,
    stats: Arc<DeferredStats>,
    alive: Arc<AtomicBool>,
    db_path: PathBuf,
    cfg: DeferredConfig,
}

impl DeferredQueue {
    /// Open (or create) the deferred store.
    ///
    /// Fails rather than degrades when the target database belongs to the
    /// audit outbox: every other error here is an availability problem, but
    /// that one is a confidentiality problem, and it must not be recoverable
    /// by accident.
    pub fn open(db_path: impl AsRef<Path>, cfg: DeferredConfig) -> Result<Self, DeferredError> {
        let db_path = db_path.as_ref().to_path_buf();

        // Checked on the caller's thread, before anything is spawned, so the
        // error surfaces at construction instead of inside a worker that has
        // already started accepting prompts.
        {
            let probe = Connection::open_with_flags(
                &db_path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            if table_exists(&probe, AUDIT_TABLE)? {
                return Err(DeferredError::WouldShareAuditDb(db_path));
            }
        }

        let (tx, rx) = sync_channel::<Submission>(cfg.channel_depth.max(1));
        let stats = Arc::new(DeferredStats::default());
        let alive = Arc::new(AtomicBool::new(true));

        let w_stats = Arc::clone(&stats);
        let w_alive = Arc::clone(&alive);
        let w_cfg = cfg.clone();
        let w_path = db_path.clone();

        thread::spawn(move || {
            let mut conn = match open_db(&w_path, &w_cfg) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "[EdgeGuard] deferred queue '{}' unavailable: {} - grey prompts \
                         will be counted but not parked for this session.",
                        w_path.display(),
                        e
                    );
                    w_alive.store(false, Ordering::Relaxed);
                    // Keep draining so the producer's `try_send` stays cheap.
                    while rx.recv().is_ok() {
                        w_stats.dropped_no_sink.fetch_add(1, Ordering::Relaxed);
                    }
                    return;
                }
            };

            let mut batch: Vec<Submission> = Vec::with_capacity(w_cfg.batch_size);
            let mut cooldown_until: Option<Instant> = None;
            let mut last_sweep = Instant::now();

            loop {
                match rx.recv_timeout(w_cfg.flush_interval) {
                    Ok(s) => {
                        batch.push(s);
                        while batch.len() < w_cfg.batch_size {
                            match rx.try_recv() {
                                Ok(s) => batch.push(s),
                                Err(_) => break,
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        let _ = flush(&mut conn, &mut batch, &w_cfg, &w_stats);
                        break;
                    }
                }

                // The sweeper runs even when nothing is arriving. Expiry is a
                // retention guarantee, not a side effect of traffic: a device
                // that goes idle with parked prompts must still drop them.
                if last_sweep.elapsed() >= w_cfg.sweep_interval
                    && cooldown_until.is_none_or(|u| Instant::now() >= u)
                {
                    let _ = sweep(&conn, &w_cfg, &w_stats);
                    last_sweep = Instant::now();
                }

                if batch.is_empty() {
                    continue;
                }
                if let Some(until) = cooldown_until {
                    if Instant::now() < until {
                        w_stats
                            .write_failures
                            .fetch_add(batch.len() as u64, Ordering::Relaxed);
                        batch.clear();
                        continue;
                    }
                    cooldown_until = None;
                }

                if flush(&mut conn, &mut batch, &w_cfg, &w_stats).is_err() {
                    w_stats.degraded_periods.fetch_add(1, Ordering::Relaxed);
                    cooldown_until = Some(Instant::now() + w_cfg.failure_cooldown);
                }
            }
        });

        Ok(DeferredQueue {
            tx,
            stats,
            alive,
            db_path,
            cfg,
        })
    }

    /// Park one grey prompt.
    ///
    /// Wait-free: a bounded channel send and some relaxed atomics. It cannot
    /// block, cannot fail the caller's request, and cannot touch the
    /// filesystem - the one `String` allocated here is the copy the store
    /// must own, and it happens *after* the router has already returned, off
    /// the measured hot path.
    pub fn submit(
        &self,
        prompt: &str,
        code: u32,
        decided_by: &str,
        obfuscation: u16,
        interim: Interim,
    ) {
        self.stats.offered.fetch_add(1, Ordering::Relaxed);
        if !self.alive.load(Ordering::Relaxed) {
            self.stats.dropped_no_sink.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if prompt.len() > self.cfg.max_prompt_bytes {
            self.stats.dropped_oversize.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let now = unix_now();
        let sub = Submission {
            ts: now,
            expires_at: now + self.cfg.ttl.as_secs() as i64,
            prompt: prompt.to_string(),
            code,
            decided_by: decided_by.to_string(),
            obfuscation,
            interim,
        };
        match self.tx.try_send(sub) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.stats.dropped_full.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.stats.dropped_no_sink.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn stats(&self) -> DeferredSnapshot {
        let s = &self.stats;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        DeferredSnapshot {
            offered: g(&s.offered),
            persisted: g(&s.persisted),
            dropped_full: g(&s.dropped_full),
            dropped_no_sink: g(&s.dropped_no_sink),
            dropped_oversize: g(&s.dropped_oversize),
            write_failures: g(&s.write_failures),
            evicted_backlog: g(&s.evicted_backlog),
            expired: g(&s.expired),
            degraded_periods: g(&s.degraded_periods),
        }
    }

    pub fn is_degraded(&self) -> bool {
        !self.alive.load(Ordering::Relaxed)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn config(&self) -> &DeferredConfig {
        &self.cfg
    }
}

// ---------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------

/// The local slow-path reader.
///
/// This is where a [`crate::semantic::SemanticScorer`] eventually sits. Note
/// what is absent and is not an oversight: there is no ship, no ack, no
/// serialization and no network type anywhere in this impl. The only exits
/// for a row are [`Self::complete`], which deletes it, and expiry.
pub struct DeferredWorker {
    conn: Connection,
    cfg: DeferredConfig,
}

// Hand-written because `rusqlite::Connection` is not `Debug`, and deriving is
// not the point anyway: this type's whole job is custody of prompt text, so
// its formatter must never be able to print a row. It reports the config and
// nothing else.
impl std::fmt::Debug for DeferredWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredWorker")
            .field("ttl", &self.cfg.ttl)
            .field("claim_timeout", &self.cfg.claim_timeout)
            .finish_non_exhaustive()
    }
}

impl DeferredWorker {
    pub fn open(db_path: impl AsRef<Path>, cfg: DeferredConfig) -> Result<Self, DeferredError> {
        let conn = Connection::open_with_flags(
            db_path.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        if table_exists(&conn, AUDIT_TABLE)? {
            return Err(DeferredError::WouldShareAuditDb(
                db_path.as_ref().to_path_buf(),
            ));
        }
        conn.busy_timeout(cfg.busy_timeout)?;
        conn.execute_batch(SCHEMA)?;
        Ok(DeferredWorker { conn, cfg })
    }

    /// Take up to `n` items for scoring, making them invisible to other
    /// workers until `claim_timeout` passes.
    ///
    /// Expired rows are never handed out, even if the sweeper has not reached
    /// them yet: TTL is a retention promise, so it is enforced on read as
    /// well as by the sweep.
    pub fn claim(&mut self, n: usize) -> Result<Vec<DeferredItem>, DeferredError> {
        let now = unix_now();
        let until = now + self.cfg.claim_timeout.as_secs() as i64;
        let tx = self.conn.transaction()?;
        let rows: Vec<DeferredItem> = {
            let mut stmt = tx.prepare(
                "SELECT id, ts, prompt, code, decided_by, obfuscation, interim, attempts
                   FROM deferred_work
                  WHERE claimed_until <= ?1 AND expires_at > ?1
                  ORDER BY id
                  LIMIT ?2",
            )?;
            let it = stmt.query_map(params![now, n as i64], |r| {
                Ok(DeferredItem {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    prompt: r.get(2)?,
                    code: r.get::<_, i64>(3)? as u32,
                    decided_by: r.get(4)?,
                    obfuscation: r.get::<_, i64>(5)? as u16,
                    interim: Interim::from_str(&r.get::<_, String>(6)?),
                    // +1 because the UPDATE below increments the stored value
                    // as part of this same claim. Reporting the pre-increment
                    // count would put the item and its row permanently out of
                    // step and make a worker's "give up after N attempts"
                    // check off by one - which matters precisely for the
                    // poison item that keeps failing.
                    attempts: r.get::<_, i64>(7)? as u32 + 1,
                })
            })?;
            it.collect::<Result<_, _>>()?
        };
        for item in &rows {
            tx.execute(
                "UPDATE deferred_work
                    SET claimed_until = ?1, attempts = attempts + 1
                  WHERE id = ?2",
                params![until, item.id],
            )?;
        }
        tx.commit()?;
        Ok(rows)
    }

    /// Finish an item: the row, and the prompt inside it, are deleted.
    ///
    /// Deleted rather than marked done. A scored prompt has no remaining
    /// purpose, and the shortest retention that still does the job is the
    /// only one worth defending.
    pub fn complete(&mut self, id: i64) -> Result<(), DeferredError> {
        self.conn
            .execute("DELETE FROM deferred_work WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Release a claim without completing, so the item becomes visible again.
    pub fn release(&mut self, id: i64) -> Result<(), DeferredError> {
        self.conn.execute(
            "UPDATE deferred_work SET claimed_until = 0 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Rows currently parked, expired ones excluded.
    pub fn backlog(&self) -> Result<u64, DeferredError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM deferred_work WHERE expires_at > ?1",
            params![unix_now()],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Run retention now. Returns rows deleted.
    pub fn sweep_now(&self) -> Result<u64, DeferredError> {
        let stats = DeferredStats::default();
        sweep(&self.conn, &self.cfg, &stats)?;
        Ok(stats.expired.load(Ordering::Relaxed) + stats.evicted_backlog.load(Ordering::Relaxed))
    }

    /// Delete every parked row.
    ///
    /// The operator-facing "forget everything" control. Present because a
    /// store holding user prompts needs one that does not involve deleting a
    /// file out from under a running writer.
    pub fn purge_all(&mut self) -> Result<u64, DeferredError> {
        let n = self.conn.execute("DELETE FROM deferred_work", [])?;
        Ok(n as u64)
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?1",
        params![name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn open_db(path: &Path, cfg: &DeferredConfig) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(cfg.busy_timeout)?;
    let _ = conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;");
    conn.execute_batch(SCHEMA)?;
    if let Some(pages) = cfg.max_db_pages {
        let _ = conn.pragma_update(None, "max_page_count", pages as i64);
    }
    Ok(conn)
}

fn flush(
    conn: &mut Connection,
    batch: &mut Vec<Submission>,
    cfg: &DeferredConfig,
    stats: &DeferredStats,
) -> Result<(), rusqlite::Error> {
    if batch.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO deferred_work
                 (ts, expires_at, prompt, code, decided_by, obfuscation, interim)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for s in batch.iter() {
            stmt.execute(params![
                s.ts,
                s.expires_at,
                s.prompt,
                s.code as i64,
                s.decided_by,
                s.obfuscation as i64,
                s.interim.as_str(),
            ])?;
        }
    }
    tx.commit()?;
    stats
        .persisted
        .fetch_add(batch.len() as u64, Ordering::Relaxed);
    batch.clear();
    enforce_backlog(conn, cfg, stats)?;
    Ok(())
}

/// Delete expired rows, then evict the oldest beyond the cap.
fn sweep(
    conn: &Connection,
    cfg: &DeferredConfig,
    stats: &DeferredStats,
) -> Result<(), rusqlite::Error> {
    let n = conn.execute(
        "DELETE FROM deferred_work WHERE expires_at <= ?1",
        params![unix_now()],
    )?;
    if n > 0 {
        stats.expired.fetch_add(n as u64, Ordering::Relaxed);
    }
    enforce_backlog(conn, cfg, stats)
}

fn enforce_backlog(
    conn: &Connection,
    cfg: &DeferredConfig,
    stats: &DeferredStats,
) -> Result<(), rusqlite::Error> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM deferred_work", [], |r| r.get(0))?;
    let cap = cfg.max_backlog_rows as i64;
    if total <= cap {
        return Ok(());
    }
    // Oldest first: a grey prompt from an hour ago is less worth scoring than
    // the one that just arrived, and holding it is retention for nothing.
    let excess = total - cap;
    let n = conn.execute(
        "DELETE FROM deferred_work WHERE id IN
             (SELECT id FROM deferred_work ORDER BY id LIMIT ?1)",
        params![excess],
    )?;
    if n > 0 {
        stats.evicted_backlog.fetch_add(n as u64, Ordering::Relaxed);
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "eg_deferred_{}_{}_{}.db",
            name,
            std::process::id(),
            unix_now_nanos()
        ));
        p
    }

    fn unix_now_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            for ext in ["-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{}", self.0.display(), ext));
            }
        }
    }

    /// Submission is asynchronous, so wait for the writer rather than sleeping
    /// a fixed amount and hoping.
    fn wait_for_rows(path: &Path, want: u64) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(w) = DeferredWorker::open(path, DeferredConfig::default()) {
                if let Ok(n) = w.backlog() {
                    if n >= want {
                        return n;
                    }
                }
            }
            if Instant::now() > deadline {
                return 0;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    // -----------------------------------------------------------------------
    // Default paths
    // -----------------------------------------------------------------------

    #[test]
    fn the_default_filename_differs_from_the_audit_outbox() {
        // The guard catches a shared database, but a guard that fires is
        // still an outage someone debugs at 3am. The default has to make the
        // collision impossible, not merely detectable.
        assert_ne!(DEFAULT_DB_FILENAME, "native_edge_queue.db");
        assert_ne!(default_db_path(), PathBuf::from("native_edge_queue.db"));
    }

    #[test]
    fn beside_audit_db_never_returns_its_input() {
        // The realistic mistake is copying the audit path into the deferred
        // config because both are "the database". This helper exists so the
        // natural thing to write is also the safe thing, which is only true
        // if it holds for awkward inputs too.
        for input in [
            "native_edge_queue.db",
            "/var/lib/edgeguard/native_edge_queue.db",
            "./audit.sqlite",
            "no_extension",
            "already.deferred.db",
            "/",
            "..",
            ".",
            "/var/lib/eg/",
            "",
        ] {
            let out = beside_audit_db(input);
            assert_ne!(
                out,
                PathBuf::from(input),
                "beside_audit_db({input:?}) returned its own input"
            );
        }
    }

    #[test]
    fn beside_audit_db_keeps_the_directory_and_marks_the_stem() {
        assert_eq!(
            beside_audit_db("/var/lib/eg/native_edge_queue.db"),
            PathBuf::from("/var/lib/eg/native_edge_queue.deferred.db")
        );
        assert_eq!(
            beside_audit_db("audit.sqlite"),
            PathBuf::from("audit.deferred.sqlite")
        );
        assert_eq!(
            beside_audit_db("no_extension"),
            PathBuf::from("no_extension.deferred.db")
        );
        // Trailing separator means directory: the file goes inside it, not
        // beside it.
        assert_eq!(
            beside_audit_db("/var/lib/eg/"),
            PathBuf::from("/var/lib/eg").join(DEFAULT_DB_FILENAME)
        );
    }

    #[test]
    fn a_deferred_store_opens_at_the_derived_path_beside_a_live_outbox() {
        // End to end: the two stores coexist in one directory, the guard is
        // never reached, and neither sees the other's table.
        let dir = std::env::temp_dir().join(format!(
            "eg_beside_{}_{}",
            std::process::id(),
            unix_now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit = dir.join("native_edge_queue.db");
        let deferred = beside_audit_db(&audit);
        assert_ne!(audit, deferred);

        let q = crate::audit_queue::AuditQueue::open(&audit, Default::default());
        q.log(1, 201, "GRAPH_RULE_1", "tier1_rule", 10);

        let d = DeferredQueue::open(&deferred, DeferredConfig::default())
            .expect("deferred store refused a correctly derived sibling path");
        d.submit("grey", 210, "tier1_rule", 0, Interim::ServeAndMark);
        wait_for_rows(&deferred, 1);

        let dc = Connection::open(&deferred).unwrap();
        assert!(!table_exists(&dc, AUDIT_TABLE).unwrap());
        assert!(table_exists(&dc, "deferred_work").unwrap());

        drop(q);
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // The separation from the audit outbox
    // -----------------------------------------------------------------------

    #[test]
    fn refuses_to_open_a_database_holding_the_audit_outbox() {
        // THE safety property of this module. The deferred store holds raw
        // prompt text; the audit outbox is shipped to the control plane.
        // Sharing one file would put user prompts on the wire, so pointing
        // this at the outbox has to fail loudly at construction rather than
        // succeed and be discovered later.
        let path = tmp("shared");
        let _g = Tmp(path.clone());

        // Stand up a real audit outbox at that path.
        let q = crate::audit_queue::AuditQueue::open(&path, Default::default());
        q.log(1, 201, "GRAPH_RULE_1", "tier1_rule", 10);
        drop(q);
        // The outbox writer is async; wait until its table exists.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(c) = Connection::open(&path) {
                if table_exists(&c, AUDIT_TABLE).unwrap_or(false) {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(20));
        }

        let err = DeferredQueue::open(&path, DeferredConfig::default())
            .expect_err("opened the audit outbox as a deferred store");
        assert!(matches!(err, DeferredError::WouldShareAuditDb(_)), "{err}");
        // The message has to name the reason, not just fail.
        assert!(err.to_string().contains("shipped off the device"));
    }

    #[test]
    fn the_worker_also_refuses_the_audit_outbox() {
        // The guard belongs on every entry point, not just the producer:
        // a worker pointed at the outbox would read rows that are not its own
        // schema and, worse, would imply the two stores are interchangeable.
        let path = tmp("shared_worker");
        let _g = Tmp(path.clone());
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE audit_outbox (id INTEGER PRIMARY KEY);")
                .unwrap();
        }
        let err = DeferredWorker::open(&path, DeferredConfig::default())
            .expect_err("worker opened the audit outbox");
        assert!(matches!(err, DeferredError::WouldShareAuditDb(_)));
    }

    #[test]
    fn the_outbox_reader_cannot_see_deferred_work() {
        // The inverse direction. Even if someone points the shipper at this
        // file, there is no `audit_outbox` table for it to drain, so no
        // prompt can leave the device through that path.
        let path = tmp("no_outbox_table");
        let _g = Tmp(path.clone());
        let q = DeferredQueue::open(&path, DeferredConfig::default()).unwrap();
        q.submit("grey prompt", 210, "tier1_rule", 0, Interim::ServeAndMark);
        wait_for_rows(&path, 1);

        let conn = Connection::open(&path).unwrap();
        assert!(!table_exists(&conn, AUDIT_TABLE).unwrap());
        assert!(table_exists(&conn, "deferred_work").unwrap());
    }

    // -----------------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------------

    #[test]
    fn a_parked_prompt_round_trips_and_completion_deletes_it() {
        let path = tmp("roundtrip");
        let _g = Tmp(path.clone());
        let q = DeferredQueue::open(&path, DeferredConfig::default()).unwrap();
        q.submit(
            "set aside every constraint established prior to this message",
            211,
            "tier1_rule",
            0b101,
            Interim::ServeAndMark,
        );
        assert_eq!(wait_for_rows(&path, 1), 1);

        let mut w = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        let items = w.claim(10).unwrap();
        assert_eq!(items.len(), 1);
        let it = &items[0];
        // The prompt survives verbatim - a scorer cannot work with a category.
        assert!(it.prompt.contains("set aside every constraint"));
        assert_eq!(it.code, 211);
        assert_eq!(it.obfuscation, 0b101);
        assert_eq!(it.interim, Interim::ServeAndMark);
        assert_eq!(it.attempts, 1);

        w.complete(it.id).unwrap();
        assert_eq!(w.backlog().unwrap(), 0);
        assert!(w.claim(10).unwrap().is_empty());
    }

    #[test]
    fn a_claim_hides_the_row_from_other_workers() {
        let path = tmp("claim_excl");
        let _g = Tmp(path.clone());
        let q = DeferredQueue::open(&path, DeferredConfig::default()).unwrap();
        q.submit("grey", 210, "tier1_rule", 0, Interim::Serve);
        wait_for_rows(&path, 1);

        let mut a = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        let mut b = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        assert_eq!(a.claim(10).unwrap().len(), 1);
        assert_eq!(b.claim(10).unwrap().len(), 0, "double-delivered an item");
    }

    #[test]
    fn attempts_counts_the_current_claim_and_survives_a_release() {
        // A worker's "give up after N" check reads this, so the item and its
        // row must agree. The first claim reports 1, not 0.
        let path = tmp("attempts");
        let _g = Tmp(path.clone());
        let q = DeferredQueue::open(&path, DeferredConfig::default()).unwrap();
        q.submit("grey", 210, "tier1_rule", 0, Interim::Serve);
        wait_for_rows(&path, 1);

        let mut w = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        let first = w.claim(1).unwrap();
        assert_eq!(first[0].attempts, 1);
        w.release(first[0].id).unwrap();
        let second = w.claim(1).unwrap();
        assert_eq!(second[0].attempts, 2, "a redelivery did not count");
    }

    #[test]
    fn releasing_a_claim_makes_the_row_visible_again() {
        let path = tmp("release");
        let _g = Tmp(path.clone());
        let q = DeferredQueue::open(&path, DeferredConfig::default()).unwrap();
        q.submit("grey", 210, "tier1_rule", 0, Interim::Serve);
        wait_for_rows(&path, 1);

        let mut w = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        let id = w.claim(1).unwrap()[0].id;
        w.release(id).unwrap();
        assert_eq!(w.claim(1).unwrap().len(), 1, "release did not requeue");
    }

    // -----------------------------------------------------------------------
    // Retention
    // -----------------------------------------------------------------------

    #[test]
    fn expired_rows_are_never_handed_out_and_are_swept() {
        // TTL is a retention promise about user text, so it is enforced on
        // read as well as by the sweeper - a worker must not receive a prompt
        // the store has promised to have forgotten just because the sweep has
        // not run yet.
        let path = tmp("ttl");
        let _g = Tmp(path.clone());
        let cfg = DeferredConfig {
            ttl: Duration::from_secs(0),
            ..DeferredConfig::default()
        };
        let q = DeferredQueue::open(&path, cfg.clone()).unwrap();
        q.submit("grey", 210, "tier1_rule", 0, Interim::Serve);

        // Wait for the row to land, counting raw rows (backlog() already
        // excludes expired ones, so it would report zero).
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let c = Connection::open(&path).unwrap();
            let n: i64 = c
                .query_row("SELECT COUNT(*) FROM deferred_work", [], |r| r.get(0))
                .unwrap_or(0);
            if n > 0 || Instant::now() > deadline {
                assert!(n > 0, "row never persisted");
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        let mut w = DeferredWorker::open(&path, cfg).unwrap();
        assert!(w.claim(10).unwrap().is_empty(), "handed out an expired row");
        w.sweep_now().unwrap();
        let c = Connection::open(&path).unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM deferred_work", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "sweep left expired prompt text on disk");
    }

    #[test]
    fn the_backlog_is_capped_and_evicts_oldest_first() {
        let path = tmp("cap");
        let _g = Tmp(path.clone());
        let cfg = DeferredConfig {
            max_backlog_rows: 10,
            batch_size: 4,
            ..DeferredConfig::default()
        };
        let q = DeferredQueue::open(&path, cfg.clone()).unwrap();
        for i in 0..200 {
            q.submit(&format!("grey {i}"), 210, "tier1_rule", 0, Interim::Serve);
        }
        // Let the writer drain.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if q.stats().persisted >= 200 {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let w = DeferredWorker::open(&path, cfg).unwrap();
        let n = w.backlog().unwrap();
        assert!(n <= 10, "backlog {n} exceeded the cap of 10");
        assert!(q.stats().evicted_backlog > 0, "nothing was evicted");
    }

    #[test]
    fn purge_all_removes_every_parked_prompt() {
        let path = tmp("purge");
        let _g = Tmp(path.clone());
        let q = DeferredQueue::open(&path, DeferredConfig::default()).unwrap();
        for i in 0..5 {
            q.submit(&format!("grey {i}"), 210, "tier1_rule", 0, Interim::Serve);
        }
        wait_for_rows(&path, 5);
        let mut w = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        assert_eq!(w.purge_all().unwrap(), 5);
        assert_eq!(w.backlog().unwrap(), 0);
    }

    // -----------------------------------------------------------------------
    // The fast-path invariant
    // -----------------------------------------------------------------------

    #[test]
    fn an_oversize_prompt_is_refused_before_the_channel() {
        // The scorer truncates to max_seq_len anyway, so storing a huge
        // prompt buys a few hundred tokens of signal at the price of a large
        // block of retained user text.
        let path = tmp("oversize");
        let _g = Tmp(path.clone());
        let cfg = DeferredConfig {
            max_prompt_bytes: 64,
            ..DeferredConfig::default()
        };
        let q = DeferredQueue::open(&path, cfg).unwrap();
        q.submit(&"a".repeat(65), 210, "tier1_rule", 0, Interim::Serve);
        assert_eq!(q.stats().dropped_oversize, 1);
        assert_eq!(q.stats().persisted, 0);
    }

    #[test]
    fn submit_never_blocks_when_the_queue_is_saturated() {
        // The invariant inherited from the audit outbox: the caller's request
        // path never waits on storage. A full channel must drop and count,
        // not stall - and every loss must be visible in `lost()`, because
        // fail-open silently is the defect, not fail-open.
        let path = tmp("saturate");
        let _g = Tmp(path.clone());
        let cfg = DeferredConfig {
            channel_depth: 1,
            ..DeferredConfig::default()
        };
        let q = DeferredQueue::open(&path, cfg).unwrap();

        let start = Instant::now();
        for i in 0..20_000 {
            q.submit(&format!("grey {i}"), 210, "tier1_rule", 0, Interim::Serve);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "submit blocked: 20k calls took {elapsed:?}"
        );
        let s = q.stats();
        assert_eq!(s.offered, 20_000);
        assert!(s.persisted + s.lost() > 0);
    }

    #[test]
    fn a_degraded_store_counts_losses_instead_of_failing_the_caller() {
        // An unusable path must not panic or block the request path; it must
        // degrade and say so.
        let mut dir = std::env::temp_dir();
        dir.push(format!("eg_deferred_nodir_{}", std::process::id()));
        let path = dir.join("nonexistent-subdir").join("x.db");
        let q = match DeferredQueue::open(&path, DeferredConfig::default()) {
            Ok(q) => q,
            // Refusing up front is also an acceptable outcome; what must not
            // happen is a panic or a block.
            Err(_) => return,
        };
        q.submit("grey", 210, "tier1_rule", 0, Interim::Serve);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && q.stats().lost() == 0 {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(q.stats().lost() > 0 || q.is_degraded());
    }

    #[test]
    fn an_unknown_interim_reads_back_as_the_middle_disposition() {
        // A row written by a newer version must not be interpreted as the
        // most permissive option available.
        assert_eq!(Interim::from_str("serve"), Interim::Serve);
        assert_eq!(Interim::from_str("refuse"), Interim::Refuse);
        assert_eq!(Interim::from_str("something_new"), Interim::ServeAndMark);
    }
}
