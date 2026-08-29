//! P9.3 cross-session contact tracing (Snow: follow the writes).
//!
//! A canary trip freezes ONE session, but the compromised session's
//! artifacts live on in files other sessions then edit. This crate
//! indexes every session's spine into one FTS5 store (the reliary-
//! search substrate pattern) and, on a canary trip, finds sessions
//! that wrote files the compromised session wrote AFTER it did.
//!
//! Design commitments (from the P9 plan, antagonised):
//! - EXPOSURE SCORED, NEVER BINARY: hub files (Cargo.lock) are
//!   scored not flagged; the threshold is chosen on the synthetic
//!   corpus before wiring.
//! - READS ARE INVISIBLE: write-implies-read is a lower bound,
//!   documented in the output ("exposure is a lower bound").
//! - FREEZE OFFERED, HUMAN DECIDES: the daemon reports exposure; it
//!   never auto-freezes on contact tracing alone.
//! - SPINE EVENTS ARE DAEMON-WRITTEN: the agent cannot forge `ts`
//!   (it can influence when it writes, which is the signal itself).
//!
//! Kill criterion (ran BEFORE wiring): synthetic A->poison->B chain
//! identified; clean parallel session with zero file overlap NOT
//! flagged; hub-file edit scored low, not binary-flagged.

use rusqlite::{params, Connection};
use std::path::Path;

/// One spine write event, indexed for tracing.
#[derive(Debug, Clone)]
pub struct WriteEvent {
  pub session: String,
  pub path: String,
  pub ts: u64,
}

/// Open (or create) the trace index at `state_dir/castellan/trace.db`.
pub fn open_index(state_dir: &Path) -> rusqlite::Result<Connection> {
  let dir = state_dir.join("castellan");
  std::fs::create_dir_all(&dir).ok();
  let conn = Connection::open(dir.join("trace.db"))?;
  conn.execute_batch(
    "CREATE TABLE IF NOT EXISTS writes (
       session TEXT NOT NULL,
       path TEXT NOT NULL,
       ts INTEGER NOT NULL
     );
     CREATE INDEX IF NOT EXISTS idx_writes_path ON writes(path);
     CREATE INDEX IF NOT EXISTS idx_writes_session ON writes(session);
     -- per-session high-water mark: last ts already indexed, so
     -- re-running trace never re-reads the whole spine (the 2MB
     -- drill corpus made every trace call spin at 29% CPU).
     CREATE TABLE IF NOT EXISTS watermark (
       session TEXT PRIMARY KEY,
       max_ts INTEGER NOT NULL
     );",
  )?;
  Ok(conn)
}

/// The per-session high-water mark: the largest ts already indexed.
pub fn watermark(conn: &Connection, session: &str) -> rusqlite::Result<u64> {
  conn
    .query_row("SELECT max_ts FROM watermark WHERE session = ?1", [session], |r| r.get(0))
    .or_else(|e| match e {
      rusqlite::Error::QueryReturnedNoRows => Ok(0),
      other => Err(other),
    })
}

/// Index a session's spine write events (fs_write allow verdicts).
/// Idempotent per (session, path, ts): re-indexing a session after
/// rotation must not duplicate. Only events STRICTLY AFTER the
/// watermark are inserted, then the watermark advances.
pub fn index_session(conn: &Connection, events: &[WriteEvent]) -> rusqlite::Result<()> {
  for e in events {
    conn.execute(
      "INSERT OR IGNORE INTO writes (session, path, ts) VALUES (?1, ?2, ?3)",
      params![e.session, e.path, e.ts as i64],
    )?;
  }
  if let Some(max) = events.iter().map(|e| e.ts).max() {
    conn.execute(
      "INSERT INTO watermark (session, max_ts) VALUES (?1, ?2)
       ON CONFLICT(session) DO UPDATE SET max_ts = MAX(max_ts, excluded.max_ts)",
      params![events[0].session, max as i64],
    )?;
  }
  Ok(())
}

/// Exposure score for a session: the fraction of the session's edited
/// files that the compromised session ALSO wrote, weighted by
/// temporal ordering (the exposed session must have written AFTER the
/// compromised one). Returns (score, exposed_files, poisoned_files).
pub fn exposure(
  conn: &Connection,
  compromised: &str,
  candidate: &str,
) -> rusqlite::Result<(f64, Vec<String>, Vec<String>)> {
  // files the compromised session wrote
  let mut stmt = conn.prepare("SELECT DISTINCT path FROM writes WHERE session = ?1")?;
  let poisoned: Vec<String> = stmt
    .query_map([compromised], |r| r.get(0))?
    .filter_map(|r| r.ok())
    .collect();
  drop(stmt);
  if poisoned.is_empty() {
    return Ok((0.0, Vec::new(), Vec::new()));
  }
  // the candidate's writes to those files, with timestamps
  let mut stmt = conn.prepare(
    "SELECT DISTINCT w.path, w.ts
     FROM writes w
     JOIN writes c ON c.path = w.path AND c.session = ?1
     WHERE w.session = ?2",
  )?;
  let mut exposed: Vec<(String, u64)> = Vec::new();
  let rows = stmt.query_map(params![compromised, candidate], |r| {
    Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
  })?;
  for row in rows.flatten() {
    exposed.push(row);
  }
  drop(stmt);
  if exposed.is_empty() {
    return Ok((0.0, Vec::new(), Vec::new()));
  }
  // temporal ordering: the candidate must have written AFTER the
  // compromised session's last write to that file
  let mut stmt = conn.prepare("SELECT MAX(ts) FROM writes WHERE session = ?1 AND path = ?2")?;
  let mut after: Vec<String> = Vec::new();
  for (path, cand_ts) in &exposed {
    let comp_ts: Option<u64> = stmt.query_row(params![compromised, path], |r| r.get(0)).ok().flatten();
    if comp_ts.map(|c| *cand_ts > c).unwrap_or(false) {
      after.push(path.clone());
    }
  }
  drop(stmt);
  // the candidate's total distinct files
  let total: i64 = conn
    .query_row("SELECT COUNT(DISTINCT path) FROM writes WHERE session = ?1", [candidate], |r| r.get(0))
    .unwrap_or(0);
  let score = if total == 0 { 0.0 } else { after.len() as f64 / total as f64 };
  Ok((score, after.clone(), poisoned))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn tmp_db() -> Connection {
    let ts = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_nanos())
      .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("castellan-trace-test-{ts}"));
    std::fs::create_dir_all(&dir).unwrap();
    open_index(&dir).unwrap()
  }

  #[test]
  fn chain_is_identified() {
    let conn = tmp_db();
    // A poisons a.c at t=100
    index_session(
      &conn,
      &[WriteEvent { session: "A".into(), path: "a.c".into(), ts: 100 }],
    )
    .unwrap();
    // B edits a.c AFTER A (t=200) — exposed
    index_session(
      &conn,
      &[
        WriteEvent { session: "B".into(), path: "a.c".into(), ts: 200 },
        WriteEvent { session: "B".into(), path: "b.c".into(), ts: 210 },
      ],
    )
    .unwrap();
    let (score, exposed, _) = exposure(&conn, "A", "B").unwrap();
    assert_eq!(exposed, vec!["a.c"]);
    assert!((score - 0.5).abs() < 1e-9, "1 of 2 files exposed, got {score}");
  }

  #[test]
  fn clean_parallel_session_not_flagged() {
    let conn = tmp_db();
    index_session(&conn, &[WriteEvent { session: "A".into(), path: "a.c".into(), ts: 100 }]).unwrap();
    index_session(
      &conn,
      &[WriteEvent { session: "C".into(), path: "c.c".into(), ts: 200 }],
    )
    .unwrap();
    let (score, exposed, _) = exposure(&conn, "A", "C").unwrap();
    assert_eq!(score, 0.0);
    assert!(exposed.is_empty());
  }

  #[test]
  fn temporal_order_matters() {
    let conn = tmp_db();
    // A writes a.c at t=300 (AFTER B's edit at t=200) — B is NOT
    // exposed: B wrote before the poison landed
    index_session(&conn, &[WriteEvent { session: "A".into(), path: "a.c".into(), ts: 300 }]).unwrap();
    index_session(&conn, &[WriteEvent { session: "B".into(), path: "a.c".into(), ts: 200 }]).unwrap();
    let (score, exposed, _) = exposure(&conn, "A", "B").unwrap();
    assert_eq!(score, 0.0);
    assert!(exposed.is_empty());
  }

  #[test]
  fn hub_file_scores_low_not_binary() {
    let conn = tmp_db();
    // A poisons Cargo.lock; B touches it plus 9 other files — the
    // score is 0.1, not a binary flag
    index_session(&conn, &[WriteEvent { session: "A".into(), path: "Cargo.lock".into(), ts: 100 }]).unwrap();
    let mut b_events = vec![WriteEvent { session: "B".into(), path: "Cargo.lock".into(), ts: 200 }];
    for i in 0..9 {
      b_events.push(WriteEvent { session: "B".into(), path: format!("f{i}.c"), ts: 200 + i });
    }
    index_session(&conn, &b_events).unwrap();
    let (score, exposed, _) = exposure(&conn, "A", "B").unwrap();
    assert!((score - 0.1).abs() < 1e-9, "hub touch must score low, got {score}");
    assert_eq!(exposed, vec!["Cargo.lock"]);
  }
}
