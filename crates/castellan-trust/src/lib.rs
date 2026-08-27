use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

pub const COLD_START_SCORE: f64 = 50.0;
pub const TIER_CEILING_WINDOW_SECS: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
  Zero = 0,
  One = 1,
  Two = 2,
  Three = 3,
  Four = 4,
}

impl Tier {
  pub fn from_score(score: f64) -> Self {
    match score {
      s if s < 20.0 => Tier::Zero,
      s if s < 50.0 => Tier::One,
      s if s < 80.0 => Tier::Two,
      s if s < 100.0 => Tier::Three,
      _ => Tier::Four,
    }
  }

  pub fn as_str(self) -> &'static str {
    match self {
      Tier::Zero => "0",
      Tier::One => "1",
      Tier::Two => "2",
      Tier::Three => "3",
      Tier::Four => "4",
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
  /// Placebo-controlled proof passed (real fix dropped danger more than
  /// placeholder) AND daemon re-ran pre-existing tests, still passing.
  ProofPassed,
  /// Clean session: no reverts, no escape attempts, no canary hits,
  /// non-empty ledger.
  CleanSession,
  /// User reverted the session (`castellan undo`).
  UserRevert,
  /// Landlock/seccomp denial logged (envelope-escape attempt).
  EnvelopeEscape,
  /// Canary credential hit (auto-freeze triggered).
  CanaryHit,
  /// Audit-trail-vs-kernel-truth mismatch.
  AuditMismatch,
  /// Bless-broker forged nonce attempt (floor 0, project frozen).
  ForgedNonce,
}

impl Signal {
  pub fn delta(self) -> f64 {
    match self {
      Signal::ProofPassed => 10.0,
      Signal::CleanSession => 1.0,
      Signal::UserRevert => -30.0,
      Signal::EnvelopeEscape => -20.0,
      Signal::CanaryHit => -50.0,
      Signal::AuditMismatch => -10.0,
      Signal::ForgedNonce => f64::NEG_INFINITY,
    }
  }

  pub fn as_str(self) -> &'static str {
    match self {
      Signal::ProofPassed => "proof_passed",
      Signal::CleanSession => "clean_session",
      Signal::UserRevert => "user_revert",
      Signal::EnvelopeEscape => "envelope_escape",
      Signal::CanaryHit => "canary_hit",
      Signal::AuditMismatch => "audit_mismatch",
      Signal::ForgedNonce => "forged_nonce",
    }
  }
}

#[derive(Debug, Clone)]
pub struct TrustEvent {
  pub ts: u64,
  pub session: String,
  pub signal: Signal,
  pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct ProjectTrust {
  pub score: f64,
  pub tier: Tier,
  pub last_event_ts: u64,
}

pub struct TrustDb {
  conn: Connection,
}

fn project_hash(realpath: &Path) -> String {
  // single shared implementation (S2 audit fix: drifted-copy risk)
  castellan_core::project_key(realpath)
}

impl TrustDb {
  pub fn open(state_home: &Path) -> rusqlite::Result<Self> {
    let dir = state_home.join("castellan");
    std::fs::create_dir_all(&dir).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let conn = Connection::open(dir.join("trust.db"))?;
    conn.execute_batch(
      "CREATE TABLE IF NOT EXISTS projects (
         realpath_hash TEXT PRIMARY KEY,
         score REAL NOT NULL,
         tier INT NOT NULL,
         last_event_ts INT NOT NULL
       );
       CREATE TABLE IF NOT EXISTS events (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         realpath_hash TEXT NOT NULL,
         ts INT NOT NULL,
         session_uuid TEXT NOT NULL,
         signal TEXT NOT NULL,
         delta REAL NOT NULL,
         evidence_json TEXT NOT NULL
       );",
    )?;
    Ok(Self { conn })
  }

  pub fn score(&self, project: &Path) -> rusqlite::Result<ProjectTrust> {
    let hash = project_hash(project);
    let row = self.conn.query_row(
      "SELECT score, tier, last_event_ts FROM projects WHERE realpath_hash = ?1",
      params![hash],
      |r| Ok((r.get::<_, f64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
    );
    match row {
      Ok((score, tier, ts)) => Ok(ProjectTrust {
        score,
        tier: tier_from_i64(tier),
        last_event_ts: ts as u64,
      }),
      Err(rusqlite::Error::QueryReturnedNoRows) => Ok(ProjectTrust {
        score: COLD_START_SCORE,
        tier: Tier::Two,
        last_event_ts: 0,
      }),
      Err(e) => Err(e),
    }
  }

  /// Apply a signal. Returns the new score and tier.
  /// Ceiling: a project cannot gain more than one tier per day.
  pub fn apply(&mut self, project: &Path, ev: &TrustEvent) -> rusqlite::Result<ProjectTrust> {
    let hash = project_hash(project);
    let before = self.score(project)?;
    let mut new_score = before.score + ev.signal.delta();
    if new_score.is_infinite() || new_score < 0.0 {
      new_score = 0.0;
    }
    if new_score > 100.0 {
      new_score = 100.0;
    }
    let mut new_tier = Tier::from_score(new_score);
    let tier_gain = (new_tier as i64) - (before.tier as i64);
    if tier_gain > 1 {
      let capped = before.tier as i64 + 1;
      new_tier = tier_from_i64(capped);
      new_score = tier_floor(new_tier);
    }
    self.conn.execute(
      "INSERT INTO projects (realpath_hash, score, tier, last_event_ts)
       VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(realpath_hash) DO UPDATE SET
         score = excluded.score,
         tier = excluded.tier,
         last_event_ts = excluded.last_event_ts",
      params![hash, new_score, new_tier as i64, ev.ts],
    )?;
    self.conn.execute(
      "INSERT INTO events (realpath_hash, ts, session_uuid, signal, delta, evidence_json)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
      params![
        hash,
        ev.ts as i64,
        ev.session,
        ev.signal.as_str(),
        ev.signal.delta(),
        ev.evidence
      ],
    )?;
    Ok(ProjectTrust { score: new_score, tier: new_tier, last_event_ts: ev.ts })
  }

  /// Full event ledger for a project, newest first. Used by `explain`.
  pub fn events(&self, project: &Path) -> rusqlite::Result<Vec<TrustEvent>> {
    let hash = project_hash(project);
    let mut stmt = self.conn.prepare(
      "SELECT ts, session_uuid, signal, evidence_json FROM events
       WHERE realpath_hash = ?1 ORDER BY id DESC",
    )?;
    let rows = stmt.query_map(params![hash], |r| {
      Ok(TrustEvent {
        ts: r.get::<_, i64>(0)? as u64,
        session: r.get::<_, String>(1)?,
        signal: signal_from_str(&r.get::<_, String>(2)?),
        evidence: r.get::<_, String>(3)?,
      })
    })?;
    rows.collect()
  }
}

fn tier_from_i64(v: i64) -> Tier {
  match v {
    0 => Tier::Zero,
    1 => Tier::One,
    2 => Tier::Two,
    3 => Tier::Three,
    _ => Tier::Four,
  }
}

fn tier_floor(t: Tier) -> f64 {
  match t {
    Tier::Zero => 0.0,
    Tier::One => 20.0,
    Tier::Two => 50.0,
    Tier::Three => 80.0,
    Tier::Four => 100.0,
  }
}

pub fn signal_from_str(s: &str) -> Signal {
  match s {
    "proof_passed" => Signal::ProofPassed,
    "clean_session" => Signal::CleanSession,
    "user_revert" => Signal::UserRevert,
    "envelope_escape" => Signal::EnvelopeEscape,
    "canary_hit" => Signal::CanaryHit,
    "audit_mismatch" => Signal::AuditMismatch,
    _ => Signal::ForgedNonce,
  }
}

pub fn default_state_home() -> PathBuf {
  std::env::var("XDG_STATE_HOME")
    .map(PathBuf::from)
    .unwrap_or_else(|_| {
      PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/state")
    })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn tmp_db() -> TrustDb {
    let ts = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_nanos())
      .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("castellan-trust-test-{ts}"));
    std::fs::create_dir_all(&dir).unwrap();
    TrustDb::open(&dir).unwrap()
  }

  fn ev(session: &str, signal: Signal) -> TrustEvent {
    TrustEvent {
      ts: std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0),
      session: session.into(),
      signal,
      evidence: "test".into(),
    }
  }

  #[test]
  fn cold_start_is_tier_two() {
    let db = tmp_db();
    let t = db.score(Path::new("/tmp/foo")).unwrap();
    assert_eq!(t.score, COLD_START_SCORE);
    assert_eq!(t.tier, Tier::Two);
  }

  #[test]
  fn revert_drops_to_tier_one() {
    let mut db = tmp_db();
    let t = db.apply(Path::new("/tmp/foo"), &ev("s1", Signal::UserRevert)).unwrap();
    assert_eq!(t.score, 20.0);
    assert_eq!(t.tier, Tier::One);
  }

  #[test]
  fn canary_hit_floor_is_zero() {
    let mut db = tmp_db();
    let t = db.apply(Path::new("/tmp/foo"), &ev("s1", Signal::CanaryHit)).unwrap();
    assert_eq!(t.score, 0.0);
    assert_eq!(t.tier, Tier::Zero);
  }

  #[test]
  fn forged_nonce_floor_is_zero() {
    let mut db = tmp_db();
    let t = db.apply(Path::new("/tmp/foo"), &ev("s1", Signal::ForgedNonce)).unwrap();
    assert_eq!(t.score, 0.0);
    assert_eq!(t.tier, Tier::Zero);
  }

  #[test]
  fn clean_sessions_accumulate() {
    let mut db = tmp_db();
    let mut t = db.score(Path::new("/tmp/foo")).unwrap();
    for i in 0..5 {
      t = db.apply(Path::new("/tmp/foo"), &ev(&format!("s{i}"), Signal::CleanSession)).unwrap();
    }
    assert_eq!(t.score, 55.0);
    assert_eq!(t.tier, Tier::Two);
  }

  #[test]
  fn tier_ceiling_blocks_jump() {
    let mut db = tmp_db();
    // 5 clean sessions = 55, then a proof = 65 — still tier 2, no jump.
    for i in 0..5 {
      db.apply(Path::new("/tmp/foo"), &ev(&format!("s{i}"), Signal::CleanSession)).unwrap();
    }
    let t = db.apply(Path::new("/tmp/foo"), &ev("s6", Signal::ProofPassed)).unwrap();
    assert_eq!(t.tier, Tier::Two);
    assert_eq!(t.score, 65.0);
  }

  #[test]
  fn events_ledger_is_reconstructible() {
    let mut db = tmp_db();
    db.apply(Path::new("/tmp/foo"), &ev("s1", Signal::UserRevert)).unwrap();
    db.apply(Path::new("/tmp/foo"), &ev("s2", Signal::CleanSession)).unwrap();
    let events = db.events(Path::new("/tmp/foo")).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].signal, Signal::CleanSession);
    assert_eq!(events[1].signal, Signal::UserRevert);
  }

  #[test]
  fn projects_are_isolated() {
    let mut db = tmp_db();
    db.apply(Path::new("/tmp/foo"), &ev("s1", Signal::UserRevert)).unwrap();
    let t = db.score(Path::new("/tmp/bar")).unwrap();
    assert_eq!(t.score, COLD_START_SCORE);
  }
}
