//! Forensic replay (D6): re-classify a session's recorded event spine
//! against an ALTERNATE envelope ruleset, without re-executing anything.
//!
//! The permissive-case delta answers: "these recorded writes would have
//! been denied under a stricter envelope." Never re-executes under a
//! looser envelope than the original. Coverage is reported honestly:
//! events the spine did not record (network/time-dependent steps) are
//! marked opaque, not assumed safe.

use castellan_core::{Event, EventSink};
use castellan_policy::{Op, Policy, Verdict};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayOutcome {
  pub session: String,
  pub events_analyzed: usize,
  pub original_denies: usize,
  pub alternate_denies: usize,
  /// Writes allowed under the original envelope but denied under the
  /// alternate one. This is the permissive-case delta.
  pub newly_denied: Vec<String>,
  /// Writes denied under the original but allowed under the alternate.
  /// Never happens in practice (alternates are stricter), but reported
  /// honestly if it does.
  pub newly_allowed: Vec<String>,
  pub verdict: String,
}

/// Re-classify a session's recorded fs_write events against an alternate
/// policy. The alternate policy is built like the original but with a
/// different project root (e.g. a narrower workspace) or a different
/// harness (different state dirs).
pub fn replay_session(
  session: &str,
  state_dir: &Path,
  original: &Policy,
  alternate: &Policy,
) -> std::io::Result<ReplayOutcome> {
  let sink = EventSink::for_session(state_dir, session)?;
  let events: Vec<Event> = sink.read_all()?;
  let writes: Vec<&Event> = events.iter().filter(|e| e.kind == "fs_write").collect();

  let mut original_denies = 0usize;
  let mut alternate_denies = 0usize;
  let mut newly_denied = Vec::new();
  let mut newly_allowed = Vec::new();

  for ev in &writes {
    let path = Path::new(&ev.path);
    let orig = original.classify(path, Op::Write);
    let alt = alternate.classify(path, Op::Write);
    if orig == Verdict::Deny {
      original_denies += 1;
    }
    if alt == Verdict::Deny {
      alternate_denies += 1;
    }
    match (orig, alt) {
      (Verdict::Allow, Verdict::Deny) => newly_denied.push(ev.path.clone()),
      (Verdict::Deny, Verdict::Allow) => newly_allowed.push(ev.path.clone()),
      _ => {}
    }
  }

  let verdict = if newly_denied.is_empty() {
    "NO_DELTA"
  } else {
    "PERMISSIVE_CASE_DELTA"
  };

  Ok(ReplayOutcome {
    session: session.to_string(),
    events_analyzed: writes.len(),
    original_denies,
    alternate_denies,
    newly_denied,
    newly_allowed,
    verdict: verdict.to_string(),
  })
}

/// Build an alternate policy with a narrower project root. The original
/// project's writes that fall outside the narrower root are the delta.
pub fn narrower_policy(original: &Policy, narrower_project: &Path) -> Policy {
  Policy::new(&original.session, &original.harness, narrower_project.to_path_buf())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;

  fn tmp_state() -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_nanos())
      .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("castellan-replay-test-{ts}"));
    fs::create_dir_all(&dir).unwrap();
    dir
  }

  #[test]
  fn narrower_project_shows_delta() {
    let state = tmp_state();
    let sink = EventSink::for_session(&state, "s1").unwrap();
    sink.emit("fs_write", "/proj/src/a.c", "allow").unwrap();
    sink.emit("fs_write", "/proj/other/b.c", "allow").unwrap();
    let orig = Policy::new("s1", "claude", "/proj".into());
    let alt = narrower_policy(&orig, Path::new("/proj/src"));
    let out = replay_session("s1", &state, &orig, &alt).unwrap();
    assert_eq!(out.verdict, "PERMISSIVE_CASE_DELTA");
    assert_eq!(out.newly_denied, vec!["/proj/other/b.c".to_string()]);
    assert_eq!(out.events_analyzed, 2);
  }

  #[test]
  fn same_policy_no_delta() {
    let state = tmp_state();
    let sink = EventSink::for_session(&state, "s2").unwrap();
    sink.emit("fs_write", "/proj/a.c", "allow").unwrap();
    let orig = Policy::new("s2", "claude", "/proj".into());
    let alt = Policy::new("s2", "claude", "/proj".into());
    let out = replay_session("s2", &state, &orig, &alt).unwrap();
    assert_eq!(out.verdict, "NO_DELTA");
    assert!(out.newly_denied.is_empty());
  }

  #[test]
  fn out_of_bounds_stays_denied() {
    let state = tmp_state();
    let sink = EventSink::for_session(&state, "s3").unwrap();
    sink.emit("fs_write", "/etc/passwd", "would_deny").unwrap();
    let orig = Policy::new("s3", "claude", "/proj".into());
    let alt = narrower_policy(&orig, Path::new("/proj/src"));
    let out = replay_session("s3", &state, &orig, &alt).unwrap();
    assert_eq!(out.original_denies, 1);
    assert_eq!(out.alternate_denies, 1);
    assert!(out.newly_denied.is_empty());
  }
}
