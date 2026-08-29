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
  // phrases (fan-out of the file, from the phrase_occ index).
  //
  // The flags byte is decoded in RUST, not SQL: SQLite's bitwise
  // operators convert a BLOB operand to an integer by parsing the
  // byte as ASCII text, so `flags & 3` on a 1-byte BLOB only works
  // when the byte happens to be an ASCII digit (0x32 = '2' passes,
  // 0x0A = newline fails). The P9.4 kill criterion passed on stria's
  // index by that accident; the fresh-index probe exposed it. The
  // packed layout (stria index/schema.rs): is_def+1 in the low 2
  // bits, zone bit 2, count bits 3-7. is_def >= 1 (packed >= 2) is
  // a definition phrase.
  let Ok(mut stmt) = conn.prepare(
    "SELECT po1.phrase_id, po1.flags
     FROM phrase_occ po1
     JOIN file_map fm ON fm.id = po1.file_id
     WHERE fm.file_path = ?1",
  ) else {
    return 1.0;
  };
  let Ok(rows) = stmt.query_map([file], |r| {
    Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
  }) else {
    return 1.0;
  };
  let mut def_phrases: Vec<i64> = Vec::new();
  for row in rows.flatten() {
    let (phrase_id, flags) = row;
    if flags.first().map(|b| (b & 0x03) >= 2).unwrap_or(false) {
      def_phrases.push(phrase_id);
    }
  }
  if def_phrases.is_empty() {
    return 0.5;
  }
  // KEYWORD FILTER: a phrase that is a DEFINITION in many files is a
  // language keyword (e.g. `int` in C, marked is_def by stria's DFA),
  // not a distinctive identifier. Only phrases whose definition-df is
  // small (<= 3) carry hubness signal. Grammar-free: pure statistics,
  // no language knowledge. Found by the synthetic-corpus probe: every
  // file scored 1.629 because `int` was a definition phrase in all 33.
  //
  // The definition-df is computed in RUST: SQLite's bitwise operators
  // parse a BLOB operand as ASCII text, so `flags & 3` in SQL only
  // works when the byte happens to be an ASCII digit (0x32 = '2'
  // passes, 0x0A = newline fails). The P9.4 kill criterion passed on
  // stria's index by that accident; the fresh-index probe exposed it.
  let placeholders = vec!["?"; def_phrases.len()].join(",");
  let occ_sql = format!(
    "SELECT po1.phrase_id, po1.file_id, po1.flags
     FROM phrase_occ po1
     WHERE po1.phrase_id IN ({placeholders})"
  );
  let occ_params: Vec<&dyn rusqlite::ToSql> =
    def_phrases.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
  let Ok(mut occ_stmt) = conn.prepare(&occ_sql) else {
    return 1.0;
  };
  let Ok(occ_rows) = occ_stmt.query_map(occ_params.as_slice(), |r| {
    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?))
  }) else {
    return 1.0;
  };
  // phrase -> set of files where it is a DEFINITION
  let mut def_files: std::collections::HashMap<i64, std::collections::HashSet<i64>> =
    std::collections::HashMap::new();
  // phrase -> set of files where it occurs at all (fan-out base)
  let mut all_files: std::collections::HashMap<i64, std::collections::HashSet<i64>> =
    std::collections::HashMap::new();
  for row in occ_rows.flatten() {
    let (phrase_id, file_id, flags) = row;
    all_files.entry(phrase_id).or_default().insert(file_id);
    if flags.first().map(|b| (b & 0x03) >= 2).unwrap_or(false) {
      def_files.entry(phrase_id).or_default().insert(file_id);
    }
  }
  let mut distinctive: Vec<i64> = Vec::new();
  for phrase_id in &def_phrases {
    if def_files.get(phrase_id).map(|s| s.len()).unwrap_or(0) <= 3 {
      distinctive.push(*phrase_id);
    }
  }
  if distinctive.is_empty() {
    return 0.5;
  }
  // fan-out: distinct files sharing any of this file's DISTINCTIVE
  // definition phrases, excluding the file itself. All placeholders
  // are positional `?` — mixing `?` and `?N` in one statement makes
  // rusqlite treat `?1` as parameter 1, colliding with the positional
  // ones (InvalidParameterCount).
  let placeholders = vec!["?"; distinctive.len()].join(",");
  let sql = format!(
    "SELECT COUNT(DISTINCT po2.file_id)
     FROM phrase_occ po2
     WHERE po2.phrase_id IN ({placeholders}) AND po2.file_id !=
       (SELECT id FROM file_map WHERE file_path = ?)"
  );
  let mut params: Vec<&dyn rusqlite::ToSql> =
    distinctive.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
  params.push(&file);
  let Ok(fanout) = conn.query_row(&sql, params.as_slice(), |r| r.get::<_, i64>(0)) else {
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
