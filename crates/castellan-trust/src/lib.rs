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
  /// P9.2: artifact scan found NEW findings in session-touched files
  /// at keep (findings-only-negative: a clean delta earns nothing).
  VulnIntroduced,
  /// Frontier round B3: a session process called a human-only daemon
  /// op over the socket (self-keep/thaw/spawn, direct trust farming,
  /// evidence poisoning, sabotage, canary oracle).
  ForgedSocketOp,
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
      Signal::VulnIntroduced => -15.0,
      Signal::ForgedSocketOp => -25.0,
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
      Signal::VulnIntroduced => "vuln_introduced",
      Signal::ForgedSocketOp => "forged_socket_op",
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
    // C14: wall-clock tier-up throttle. Best-effort migration for
    // pre-C14 databases (ALTER fails if the column already exists).
    let _ = conn.execute(
      "ALTER TABLE projects ADD COLUMN last_tier_up_ts INT NOT NULL DEFAULT 0",
      [],
    );
    Ok(Self { conn })
  }

  pub fn score(&self, project: &Path) -> rusqlite::Result<ProjectTrust> {
    let hash = project_hash(project);
    // last_tier_up_ts may be absent on pre-C14 databases opened
    // read-only paths; fall back to 0 (window open) on schema mismatch.
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
    self.apply_weighted(project, ev, 1.0)
  }

  /// Apply a signal with a blast-radius weight (P9.4). The weight
  /// scales the delta: a hub-function fix earns more, a hub-function
  /// regression costs more. Weight 1.0 = neutral (no index).
  pub fn apply_weighted(
    &mut self,
    project: &Path,
    ev: &TrustEvent,
    weight: f64,
  ) -> rusqlite::Result<ProjectTrust> {
    let hash = project_hash(project);
    let before = self.score(project)?;
    // C14: wall-clock tier-up throttle + tier-3 proof gate need the
    // project's tier-up history and proof ledger. Both are best-effort
    // reads (pre-C14 schemas fall back to open window / no proof).
    let last_up: u64 = self
      .conn
      .query_row(
        "SELECT last_tier_up_ts FROM projects WHERE realpath_hash = ?1",
        params![hash],
        |r| r.get::<_, i64>(0),
      )
      .map(|v| v as u64)
      .unwrap_or(0);
    let has_proof: bool = self
      .conn
      .query_row(
        "SELECT COUNT(*) FROM events WHERE realpath_hash = ?1 AND signal = 'proof_passed'",
        params![hash],
        |r| r.get::<_, i64>(0),
      )
      .map(|n| n > 0)
      .unwrap_or(false);
    let mut new_score = before.score + ev.signal.delta() * weight;
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
    // C14a: wall-clock window. Score is NEVER clamped: the ledger is
    // honest about what happened. The TIER does not follow upward until
    // TIER_CEILING_WINDOW_SECS have passed since the last tier-up — the
    // stored tier stays, and last_tier_up_ts is untouched, so the
    // tier-up lands on the first apply after the window opens. The
    // window binds on UPGRADES only: downgrades (tier_gain <= 0) always
    // land immediately — a canary trip floors the project the same
    // second, never deferred.
    let mut new_last_up = last_up;
    if new_tier as i64 > before.tier as i64 {
      if ev.ts.saturating_sub(last_up) < TIER_CEILING_WINDOW_SECS {
        new_tier = before.tier;
      } else {
        new_last_up = ev.ts;
      }
    }
    // C14b: tier-3 evidentiary gate. Tier 3 is the first tier that
    // widens the expansion surface beyond the tier-2 default, so entry
    // requires a Factor-B proof row in the project's ledger — 30 farmed
    // keeps (R3-lite) buy score but not the tier. The tier stays at 2
    // (score untouched); entry lands on the first apply after a proof
    // row exists. Downgrades are unaffected.
    if new_tier == Tier::Three && before.tier as i64 <= Tier::Two as i64 && !has_proof {
      new_tier = Tier::Two;
    }
    self.conn.execute(
      "INSERT INTO projects (realpath_hash, score, tier, last_event_ts, last_tier_up_ts)
       VALUES (?1, ?2, ?3, ?4, ?5)
       ON CONFLICT(realpath_hash) DO UPDATE SET
         score = excluded.score,
         tier = excluded.tier,
         last_event_ts = excluded.last_event_ts,
         last_tier_up_ts = excluded.last_tier_up_ts",
      params![hash, new_score, new_tier as i64, ev.ts, new_last_up as i64],
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

/// Highest score that still maps to `t` (exclusive upper bound minus
/// epsilon). Kept for the K1-style marginal analysis; C14 no longer
/// clamps score (only the tier is held), so this is test/doc support.
#[allow(dead_code)]
fn tier_ceiling(t: Tier) -> f64 {
  match t {
    Tier::Zero => 20.0 - 0.1,
    Tier::One => 50.0 - 0.1,
    Tier::Two => 80.0 - 0.1,
    Tier::Three => 100.0 - 0.1,
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
    "forged_nonce" => Signal::ForgedNonce,
    "vuln_introduced" => Signal::VulnIntroduced,
    "forged_socket_op" => Signal::ForgedSocketOp,
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
  fn signal_names_round_trip() {
    // every Signal must survive a ledger write + read without aliasing
    // to another signal (V3 antagonism: forged_socket_op and
    // vuln_introduced previously fell through to ForgedNonce).
    let signals = [
      Signal::ProofPassed,
      Signal::CleanSession,
      Signal::UserRevert,
      Signal::EnvelopeEscape,
      Signal::CanaryHit,
      Signal::AuditMismatch,
      Signal::ForgedNonce,
      Signal::VulnIntroduced,
      Signal::ForgedSocketOp,
    ];
    for sig in signals {
      assert_eq!(signal_from_str(sig.as_str()), sig, "round-trip for {}", sig.as_str());
    }
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

  fn ev_at(ts: u64, session: &str, signal: Signal) -> TrustEvent {
    TrustEvent { ts, session: session.into(), signal, evidence: "test".into() }
  }

  #[test]
  fn c14_window_blocks_rapid_second_tier_up() {
    // C14a: the wall-clock window throttles tier-ups to one per
    // TIER_CEILING_WINDOW_SECS. Tier 1 -> 2 lands (first tier-up from a
    // zero last_tier_up_ts is outside the window); a further climb
    // holds the TIER at 2 while the score keeps its honest earned
    // position. Fixed iteration count (no `while score < 80` — the
    // held tier no longer stops score growth, but fixed counts
    // terminate regardless).
    let mut db = tmp_db();
    let p = Path::new("/tmp/c14window");
    db.apply(p, &ev_at(1_000_000, "s0", Signal::UserRevert)).unwrap();
    db.apply(p, &ev_at(1_000_001, "s1", Signal::ProofPassed)).unwrap();
    let mut t = db.score(p).unwrap();
    for i in 2..42u64 {
      t = db.apply(p, &ev_at(1_000_000 + i, &format!("k{i}"), Signal::CleanSession)).unwrap();
    }
    assert_eq!(t.tier, Tier::Two, "window must hold tier at 2");
    assert!(t.score >= 70.0, "score keeps its honest position, got {}", t.score);
  }

  #[test]
  fn c14_window_opens_after_24h() {
    // C14a, second half: once TIER_CEILING_WINDOW_SECS have passed
    // since the last tier-up, the tier follows the score.
    let mut db = tmp_db();
    let p = Path::new("/tmp/c14open");
    db.apply(p, &ev_at(1_000_000, "s0", Signal::UserRevert)).unwrap();
    db.apply(p, &ev_at(1_000_001, "s1", Signal::ProofPassed)).unwrap();
    let mut t = db.score(p).unwrap();
    for i in 2..42u64 {
      t = db.apply(p, &ev_at(1_000_000 + i, &format!("k{i}"), Signal::CleanSession)).unwrap();
    }
    assert_eq!(t.tier, Tier::Two);
    assert!(t.score >= 70.0, "honest score position, got {}", t.score);
    // two more windows of keeps push the honest score past 80; the
    // tier follows on the window-open apply (proof row from s1 keeps
    // C14b open).
    let mut t2 = t;
    for i in 42..72u64 {
      t2 = db.apply(
        p,
        &ev_at(1_000_001 + TIER_CEILING_WINDOW_SECS + i, &format!("w{i}"), Signal::CleanSession),
      ).unwrap();
    }
    assert!(t2.score >= 80.0, "honest score past 80, got {}", t2.score);
    assert_eq!(t2.tier, Tier::Three, "window open + proof present must enter tier 3");
  }

  #[test]
  fn c14_tier3_needs_proof() {
    // C14b: 30 farmed keeps (R3-lite shape) buy score but NOT tier 3
    // without a proof_passed row in the ledger. Score is unclamped
    // (honest position 80.0); only the tier is held.
    let mut db = tmp_db();
    let p = Path::new("/tmp/c14farm");
    // spread applies over 3 windows so C14a never binds; only C14b can.
    let mut t = db.score(p).unwrap();
    for i in 0..30u64 {
      t = db.apply(
        p,
        &ev_at(1_000_000 + i * (TIER_CEILING_WINDOW_SECS + 10), &format!("f{i}"), Signal::CleanSession),
      ).unwrap();
    }
    assert!(t.score >= 80.0, "farmed score keeps honest position, got {}", t.score);
    assert_eq!(t.tier, Tier::Two, "farmed score without proof must not enter tier 3");
  }

  #[test]
  fn c14_tier3_opens_with_proof() {
    // C14b, second half: the same farm WITH a proof row enters tier 3
    // once the window is open.
    let mut db = tmp_db();
    let p = Path::new("/tmp/c14proof");
    db.apply(p, &ev_at(1_000_000, "p0", Signal::ProofPassed)).unwrap();
    let mut t = db.score(p).unwrap();
    for i in 1..30u64 {
      t = db.apply(
        p,
        &ev_at(1_000_000 + i * (TIER_CEILING_WINDOW_SECS + 10), &format!("f{i}"), Signal::CleanSession),
      ).unwrap();
    }
    assert_eq!(t.tier, Tier::Three, "proof present + window open must enter tier 3");
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
