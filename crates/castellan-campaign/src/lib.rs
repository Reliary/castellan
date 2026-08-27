//! Campaign detector (N1): cross-session slow-drip attack detection.
//!
//! T1: an attack split across sessions/days defeats per-session spines
//! and per-session detection. This detector runs over the project's
//! cross-session trust-event stream (trust.db events ledger) and looks
//! for campaign-shaped sequences:
//!
//! - a session that ends in a negative signal (revert, canary hit,
//!   envelope escape) is a "bad session";
//! - a campaign is a run of bad sessions with no intervening good
//!   session, or a bad session preceded by suspicious escalation
//!   (canary hit after a revert, etc.);
//! - the detector reports the campaign window, the sessions in it, and
//!   the dominant negative signal.
//!
//! Grammar-free: works on the signal stream only, no per-language code.
//! Advisory: it never freezes (N2 routing — low confidence).

pub mod signature;

use castellan_core::ResponseTier;
use castellan_trust::{Signal, TrustDb, signal_from_str};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
  pub project: String,
  pub sessions_scanned: usize,
  pub campaigns: Vec<Campaign>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
  pub start_ts: u64,
  pub end_ts: u64,
  pub sessions: Vec<String>,
  pub dominant_signal: String,
  pub severity: String,
}

/// A session's outcome as seen from the trust-event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
  Good,
  Bad,
}

fn outcome(signal: Signal) -> Outcome {
  match signal {
    Signal::ProofPassed | Signal::CleanSession => Outcome::Good,
    Signal::UserRevert | Signal::CanaryHit | Signal::EnvelopeEscape | Signal::AuditMismatch => {
      Outcome::Bad
    }
    Signal::ForgedNonce => Outcome::Bad,
  }
}

/// Severity order for tie-breaking the dominant signal: canary hit and
/// envelope escape outrank reverts.
fn signal_rank(signal: Signal) -> u8 {
  match signal {
    Signal::CanaryHit | Signal::EnvelopeEscape => 3,
    Signal::ForgedNonce => 2,
    Signal::UserRevert | Signal::AuditMismatch => 1,
    Signal::ProofPassed | Signal::CleanSession => 0,
  }
}

/// Scan a project's cross-session event stream for campaigns.
/// A campaign is a maximal run of bad sessions with no good session
/// in between. Severity: "high" if any canary hit or envelope escape
/// is in the run, "medium" if only reverts, "low" otherwise.
pub fn detect_campaigns(project: &Path, state_home: &Path) -> std::io::Result<CampaignReport> {
  let db = TrustDb::open(state_home).map_err(|e| {
    std::io::Error::new(std::io::ErrorKind::Other, format!("trust db open: {e}"))
  })?;
  let events = db.events(project).map_err(|e| {
    std::io::Error::new(std::io::ErrorKind::Other, format!("trust events: {e}"))
  })?;
  // events come back newest-first; reverse to chronological
  let mut events = events;
  events.reverse();

  let mut campaigns: Vec<Campaign> = Vec::new();
  let mut current: Option<Campaign> = None;
  let mut sessions_scanned = 0usize;

  for ev in &events {
    let o = outcome(ev.signal);
    match o {
      Outcome::Good => {
        // a good session breaks any in-progress campaign
        if let Some(c) = current.take() {
          campaigns.push(c);
        }
      }
      Outcome::Bad => {
        sessions_scanned += 1;
        match current.as_mut() {
          Some(c) => {
            c.end_ts = ev.ts;
            if !c.sessions.contains(&ev.session) {
              c.sessions.push(ev.session.clone());
            }
          }
          None => {
            current = Some(Campaign {
              start_ts: ev.ts,
              end_ts: ev.ts,
              sessions: vec![ev.session.clone()],
              dominant_signal: ev.signal.as_str().to_string(),
              severity: String::new(),
            });
          }
        }
      }
    }
  }
  if let Some(c) = current.take() {
    campaigns.push(c);
  }

  // severity + dominant signal per campaign
  for c in &mut campaigns {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut has_canary = false;
    let mut has_escape = false;
    for ev in &events {
      if c.sessions.contains(&ev.session) {
        *counts.entry(ev.signal.as_str().to_string()).or_insert(0) += 1;
        if matches!(ev.signal, Signal::CanaryHit) {
          has_canary = true;
        }
        if matches!(ev.signal, Signal::EnvelopeEscape) {
          has_escape = true;
        }
      }
    }
    c.dominant_signal = counts
      .iter()
      .max_by_key(|(s, n)| {
        let rank = signal_rank(signal_from_str(s));
        (*n, rank)
      })
      .map(|(s, _)| s.clone())
      .unwrap_or_else(|| "unknown".into());
    c.severity = if has_canary || has_escape {
      "high".into()
    } else if c.dominant_signal == "user_revert" {
      "medium".into()
    } else {
      "low".into()
    };
  }

  Ok(CampaignReport {
    project: project.display().to_string(),
    sessions_scanned,
    campaigns,
  })
}

/// N2 routing: campaign detection is low-confidence — silent.
pub fn tier() -> ResponseTier {
  ResponseTier::Silent
}

#[cfg(test)]
mod tests {
  use super::*;
  use castellan_trust::{TrustDb, TrustEvent};
  use std::fs;

  fn tmp_home() -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_nanos())
      .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("castellan-campaign-test-{ts}"));
    fs::create_dir_all(&dir).unwrap();
    dir
  }

  fn ev(ts: u64, session: &str, signal: Signal) -> TrustEvent {
    TrustEvent {
      ts,
      session: session.to_string(),
      signal,
      evidence: "test".into(),
    }
  }

  #[test]
  fn single_bad_session_is_a_campaign() {
    let home = tmp_home();
    let proj = Path::new("/tmp/campaign-proj");
    let mut db = TrustDb::open(&home).unwrap();
    db.apply(proj, &ev(100, "s1", Signal::UserRevert)).unwrap();
    let report = detect_campaigns(proj, &home).unwrap();
    assert_eq!(report.campaigns.len(), 1);
    assert_eq!(report.campaigns[0].sessions, vec!["s1"]);
    assert_eq!(report.campaigns[0].severity, "medium");
  }

  #[test]
  fn good_session_breaks_a_campaign() {
    let home = tmp_home();
    let proj = Path::new("/tmp/campaign-proj2");
    let mut db = TrustDb::open(&home).unwrap();
    db.apply(proj, &ev(100, "s1", Signal::UserRevert)).unwrap();
    db.apply(proj, &ev(200, "s2", Signal::CleanSession)).unwrap();
    db.apply(proj, &ev(300, "s3", Signal::UserRevert)).unwrap();
    let report = detect_campaigns(proj, &home).unwrap();
    assert_eq!(report.campaigns.len(), 2);
    assert_eq!(report.campaigns[0].sessions, vec!["s1"]);
    assert_eq!(report.campaigns[1].sessions, vec!["s3"]);
  }

  #[test]
  fn canary_hit_escalates_severity() {
    let home = tmp_home();
    let proj = Path::new("/tmp/campaign-proj3");
    let mut db = TrustDb::open(&home).unwrap();
    db.apply(proj, &ev(100, "s1", Signal::UserRevert)).unwrap();
    db.apply(proj, &ev(200, "s2", Signal::CanaryHit)).unwrap();
    let report = detect_campaigns(proj, &home).unwrap();
    assert_eq!(report.campaigns.len(), 1);
    assert_eq!(report.campaigns[0].severity, "high");
    assert_eq!(report.campaigns[0].dominant_signal, "canary_hit");
  }

  #[test]
  fn empty_stream_has_no_campaigns() {
    let home = tmp_home();
    let proj = Path::new("/tmp/campaign-proj4");
    let report = detect_campaigns(proj, &home).unwrap();
    assert!(report.campaigns.is_empty());
    assert_eq!(report.sessions_scanned, 0);
  }
}
