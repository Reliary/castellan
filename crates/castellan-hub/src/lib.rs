//! P9.4 blast-radius-weighted trust.
//!
//! A leaf-file fix earns the same trust as a hub-function edit today.
//! This crate weights trust signals by the structural risk of what
//! was touched, using the stria phrase index (grammar-free, pure
//! Rust — NOT quale, whose hub_risk is Python and violates the
//! trusted-path rule).
//!
//! Design commitments (from the P9 plan, antagonised):
//! - ASYNC, NEVER BLOCKS SPAWN: the index build runs in a background
//!   thread; the default weight is 1.0 until the index is ready. No
//!   penalty for a missing index.
//! - WEIGHTING, NOT ENFORCEMENT: a wrong hub score distorts a trust
//!   delta, never freezes anyone.
//! - WEIGHT FLOOR 0.5: new files have no history; generated-looking
//!   churn (lockfiles) is damped by path-segment rules (the symbol.rs
//!   lesson: segments, not substrings).
//! - The placebo pair still gates: danger must actually drop.
//!
//! Kill criterion (ran BEFORE wiring): on stria's own repo, hub-file
//! edits vs leaf edits produce measurably different weights across
//! >= 20 synthetic sessions (sign test, not eyeballing).

use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// Weight in [0.5, 2.0] for a touched file. 1.0 = neutral (no index,
/// unknown file, or average hubness).
pub fn file_weight(db_path: &Path, file: &str) -> f64 {
  // path-segment damping: generated/lockfile churn is never a hub
  let lower = file.to_ascii_lowercase();
  for seg in lower.split('/') {
    if seg == "lock" || seg == "lockfile" || seg == "package-lock.json" || seg == "cargo.lock" {
      return 0.5;
    }
  }
  let Ok(conn) = Connection::open(db_path) else {
    return 1.0;
  };
  // hubness = number of files referencing this file's DEFINITION
  // phrases (fan-out of the file, from the phrase_occ index). Only
  // definition phrases count (flags & 0x03 >= 2, the is_def > 0
  // filter stria's blast_radius uses) — common keywords would make
  // every file look like a hub. Grammar-free: no parsers involved.
  let Ok(mut stmt) = conn.prepare(
    "SELECT COUNT(DISTINCT po2.file_id)
     FROM phrase_occ po1
     JOIN phrase_occ po2 ON po1.phrase_id = po2.phrase_id AND po1.file_id != po2.file_id
     JOIN file_map fm ON fm.id = po1.file_id
     WHERE fm.file_path = ?1 AND (po1.flags & 3) >= 2",
  ) else {
    return 1.0;
  };
  let Ok(fanout) = stmt.query_row([file], |r| r.get::<_, i64>(0)) else {
    return 1.0;
  };
  // map fan-out to [0.5, 2.0]: 0 refs -> 0.5, ~10 refs -> 1.0,
  // 100+ refs -> 2.0 (log scale)
  if fanout <= 0 {
    return 0.5;
  }
  let w = 0.5 + 1.5 * (fanout as f64).ln() / (100.0_f64).ln();
  w.clamp(0.5, 2.0)
}

/// Weight for a set of touched files: the max (the riskiest touch
/// dominates — a session that touches one hub file is riskier than
/// one that touches many leaves).
pub fn session_weight(db_path: &Path, touched: &[String]) -> f64 {
  touched
    .iter()
    .map(|f| file_weight(db_path, f))
    .fold(1.0, |acc, w| acc.max(w))
}

/// The stria index path for a project: `<project>/.stria/phrases.sqlite`.
pub fn index_path(project: &Path) -> PathBuf {
  project.join(".stria/phrases.sqlite")
}

/// sha256 of the stria index, or None if it does not exist. The
/// P9.4 weight is read at keep from a file inside the agent's write
/// roots; the spawn-time pin is the authority (see Session::hub_index_sha).
pub fn index_sha(project: &Path) -> Option<String> {
  use sha2::{Digest, Sha256};
  let path = index_path(project);
  let bytes = std::fs::read(&path).ok()?;
  let mut h = Sha256::new();
  h.update(&bytes);
  Some(format!("{:x}", h.finalize()))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn missing_index_is_neutral() {
    let w = file_weight(Path::new("/nonexistent/x.sqlite"), "a.c");
    assert_eq!(w, 1.0);
  }

  #[test]
  fn lockfile_churn_is_damped() {
    let w = file_weight(Path::new("/nonexistent/x.sqlite"), "Cargo.lock");
    assert_eq!(w, 0.5);
  }

  #[test]
  fn session_weight_takes_max() {
    let w = session_weight(Path::new("/nonexistent/x.sqlite"), &["a.c".into(), "Cargo.lock".into()]);
    assert_eq!(w, 1.0);
  }

  #[test]
  fn index_path_is_under_stria() {
    let p = index_path(Path::new("/proj"));
    assert_eq!(p, PathBuf::from("/proj/.stria/phrases.sqlite"));
  }
}
