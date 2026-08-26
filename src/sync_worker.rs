use reqwest::blocking::Client;
use rusqlite::{Connection, Result};
use serde::Serialize;
use std::thread;
use std::time::Duration;

const SYNC_INTERVAL: Duration = Duration::from_secs(3);
const DASHBOARD_URL: &str = "http://localhost:8080/api/events";

#[derive(Serialize)]
struct SyncEvent {
    id: i64,
    prompt: String,
    response: String,
    latency: f64,
    tps: f64,
    guardrail_passed: bool,
    status: String,
    created_at: String,
}

pub fn start(db_path: String) {
    thread::spawn(move || {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client for sync worker");

        loop {
            let _ = sync_batch(&client, &db_path);
            thread::sleep(SYNC_INTERVAL);
        }
    });
}

fn sync_batch(client: &Client, db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)?;
    let events = fetch_pending(&conn)?;

    if events.is_empty() {
        return Ok(());
    }

    let ids: Vec<i64> = events.iter().map(|e| e.id).collect();

    match client.post(DASHBOARD_URL).json(&events).send() {
        Ok(response) if response.status().is_success() => {
            mark_synced(&conn, &ids)?;
            println!(
                "[Sync Worker] Synced {} event(s) to dashboard.",
                ids.len()
            );
        }
        Ok(response) => {
            let _ = response.status();
            // Server responded with an error — leave events PENDING for retry.
        }
        Err(_) => {
            // Dashboard offline — retry silently on the next interval.
        }
    }

    Ok(())
}

fn fetch_pending(conn: &Connection) -> Result<Vec<SyncEvent>> {
    let mut stmt = conn.prepare(
        "SELECT id, prompt, response, latency_sec, tps, guardrail_passed, sync_status, created_at
         FROM native_events
         WHERE sync_status = 'PENDING'
         ORDER BY id ASC",
    )?;

    let events = stmt
        .query_map([], |row| {
            Ok(SyncEvent {
                id: row.get(0)?,
                prompt: row.get(1)?,
                response: row.get(2)?,
                latency: row.get(3)?,
                tps: row.get(4)?,
                guardrail_passed: row.get::<_, i64>(5)? != 0,
                status: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;

    Ok(events)
}

fn mark_synced(conn: &Connection, ids: &[i64]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    for id in ids {
        tx.execute(
            "UPDATE native_events SET sync_status = 'SYNCED' WHERE id = ?1",
            [id],
        )?;
    }
    tx.commit()?;
    Ok(())
}
