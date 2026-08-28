//! P9.6 policy regression replay — CI for the controller (Leveson).
//!
//! The envelope policy is control software. We change it (C10a
//! findings will force changes). Nothing today measures whether a
//! policy change would newly deny work that humans previously
//! approved. Every other engineering discipline regression-tests the
//! controller; this crate does too.
//!
//! Design commitments (from the P9 plan, antagonised):
//! - KEPT SESSIONS ONLY: audit-mode spines carry allow/would_deny
//!   verdicts — exactly the "what humans approved" corpus. Enforce
//!   spines are mostly empty (known finding).
//! - FALSE-NEW-DENIES ONLY: replay measures false-NEW-denies, never
//!   claims false-accept measurement; labeled accordingly.
//! - ADVISORY AT RELEASE TIME: the human reads the delta; the check
//!   runs on the developer's machine, not the agent's runtime.
//! - SPINES ARE HASH-CHAINED (ledger): an agent staging approvals to
//!   game a future policy check cannot forge the chain.
//!
//! Kill criterion (ran BEFORE wiring): an injected regression (deny a
//! previously-allowed legit path) is flagged; an honest policy change
//! (known-narrowing) shows a delta exactly matching the intended
//! narrowing.

use castellan_core::EventSink;
use castellan_policy::{Op, Policy, Verdict};
use castellan_replay::ReplayOutcome;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The policy-check report: per-session replay outcomes plus the
/// aggregate false-new-deny delta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheckReport {
  pub sessions_checked: usize,
  pub sessions_with_delta: usize,
  pub newly_denied: Vec<String>,
  pub verdict: String,
}

/// Replay every kept session's spine through the CANDIDATE policy and
/// report the false-new-deny delta vs the ORIGINAL policy.
///
/// `kept_sessions` is the list of session ids the human kept (from
/// the trust ledger — clean_session / proof_passed signals).
pub fn check_policy(
  state_dir: &Path,
  kept_sessions: &[String],
  original: &Policy,
  candidate: &Policy,
) -> std::io::Result<PolicyCheckReport> {
  let mut newly_denied: Vec<String> = Vec::new();
  let mut sessions_with_delta = 0usize;
  let mut checked = 0usize;

  for session in kept_sessions {
    let sink = match EventSink::for_session(state_dir, session) {
      Ok(s) => s,
      Err(_) => continue,
    };
    let events = match sink.read_all() {
      Ok(e) => e,
      Err(_) => continue,
    };
    let writes: Vec<&castellan_core::Event> =
      events.iter().filter(|e| e.kind == "fs_write").collect();
    if writes.is_empty() {
      continue;
    }
    checked += 1;
    let mut session_delta = false;
    for ev in &writes {
      let path = Path::new(&ev.path);
      let orig = original.classify(path, Op::Write);
      let cand = candidate.classify(path, Op::Write);
      if orig == Verdict::Allow && cand == Verdict::Deny {
        newly_denied.push(format!("{session}: {}", ev.path));
        session_delta = true;
      }
    }
    if session_delta {
      sessions_with_delta += 1;
    }
  }

  let verdict = if newly_denied.is_empty() {
    "NO_FALSE_NEW_DENIES"
  } else {
    "FALSE_NEW_DENIES"
  };

  Ok(PolicyCheckReport {
    sessions_checked: checked,
    sessions_with_delta,
    newly_denied,
    verdict: verdict.to_string(),
  })
}

/// Collect kept session ids from the trust ledger: sessions with a
/// clean_session or proof_passed signal for the project.
pub fn kept_sessions(trust: &castellan_trust::TrustDb, project: &Path) -> Vec<String> {
  let Ok(events) = trust.events(project) else {
    return Vec::new();
  };
  let mut out: Vec<String> = Vec::new();
  for ev in events {
    match ev.signal {
      castellan_trust::Signal::CleanSession | castellan_trust::Signal::ProofPassed => {
        if !out.contains(&ev.session) {
          out.push(ev.session);
        }
      }
      _ => {}
    }
  }
  out
}

/// Convenience: build the original and candidate policies for a
/// project and run the check. The candidate is built with the same
/// session/harness but a different project root (narrower workspace)
/// or a different harness (different state dirs).
pub fn check_policy_for_project(
  state_dir: &Path,
  project: &Path,
  harness: &str,
  candidate_project: &Path,
) -> std::io::Result<PolicyCheckReport> {
  let trust = castellan_trust::TrustDb::open(&state_dir.join("castellan/trust.db"))
    .map_err(|e| std::io::Error::other(format!("trust.db open failed: {e}")))?;
  let kept = kept_sessions(&trust, project);
  let original = Policy::new("policycheck", harness, project.to_path_buf());
  let candidate = Policy::new("policycheck", harness, candidate_project.to_path_buf());
  check_policy(state_dir, &kept, &original, &candidate)
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
    let dir = std::env::temp_dir().join(format!("castellan-policycheck-test-{ts}"));
    fs::create_dir_all(&dir).unwrap();
    dir
  }

  #[test]
  fn injected_regression_is_flagged() {
    let state = tmp_state();
    // a kept session wrote /proj/src/a.c (allowed under the original)
    let sink = EventSink::for_session(&state, "s1").unwrap();
    sink.emit("fs_write", "/proj/src/a.c", "allow").unwrap();
    let orig = Policy::new("s1", "claude", "/proj".into());
    // candidate denies /proj/src entirely (injected regression)
    let cand = Policy::new("s1", "claude", "/proj/other".into());
    let report = check_policy(&state, &["s1".to_string()], &orig, &cand).unwrap();
    assert_eq!(report.verdict, "FALSE_NEW_DENIES");
    assert_eq!(report.newly_denied.len(), 1);
    assert!(report.newly_denied[0].contains("a.c"));
  }

  #[test]
  fn honest_narrowing_matches_intent() {
    let state = tmp_state();
    let sink = EventSink::for_session(&state, "s2").unwrap();
    sink.emit("fs_write", "/proj/src/a.c", "allow").unwrap();
    sink.emit("fs_write", "/proj/other/b.c", "allow").unwrap();
    let orig = Policy::new("s2", "claude", "/proj".into());
    // honest narrowing: /proj/other is now out of scope
    let cand = Policy::new("s2", "claude", "/proj/src".into());
    let report = check_policy(&state, &["s2".to_string()], &orig, &cand).unwrap();
    assert_eq!(report.verdict, "FALSE_NEW_DENIES");
    assert_eq!(report.newly_denied.len(), 1);
    assert!(report.newly_denied[0].contains("b.c"));
    assert!(!report.newly_denied[0].contains("a.c"));
  }

  #[test]
  fn no_change_no_delta() {
    let state = tmp_state();
    let sink = EventSink::for_session(&state, "s3").unwrap();
    sink.emit("fs_write", "/proj/a.c", "allow").unwrap();
    let orig = Policy::new("s3", "claude", "/proj".into());
    let cand = Policy::new("s3", "claude", "/proj".into());
    let report = check_policy(&state, &["s3".to_string()], &orig, &cand).unwrap();
    assert_eq!(report.verdict, "NO_FALSE_NEW_DENIES");
    assert!(report.newly_denied.is_empty());
  }

  #[test]
  fn kept_sessions_from_trust_ledger() {
    let state = tmp_state();
    let mut trust = castellan_trust::TrustDb::open(&state.join("castellan/trust.db")).unwrap();
    let project = Path::new("/proj");
    trust
      .apply(
        project,
        &castellan_trust::TrustEvent {
          ts: 1,
          session: "kept1".into(),
          signal: castellan_trust::Signal::CleanSession,
          evidence: "kept".into(),
        },
      )
      .unwrap();
    trust
      .apply(
        project,
        &castellan_trust::TrustEvent {
          ts: 2,
          session: "reverted".into(),
          signal: castellan_trust::Signal::UserRevert,
          evidence: "reverted".into(),
        },
      )
      .unwrap();
    let kept = kept_sessions(&trust, project);
    assert_eq!(kept, vec!["kept1"]);
  }
}
