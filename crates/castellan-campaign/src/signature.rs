//! Scale-invariant campaign signatures (P8.2).
//!
//! Science: Mellin (1937) — scale invariance. T1: the same attack
//! stretched over 3 weeks defeats every per-session and windowed
//! detector. Under scale transform, a 3-hour attack and its 3-week
//! dilation are the same object.
//!
//! Honest math framing: event streams are discrete; we do NOT compute
//! a continuous Mellin transform. Per-kind time-histograms (fraction
//! of each event kind's mass in each of 10 normalized-time bins) are
//! the discrete Mellin-domain sampling: log-time sampling is the
//! discrete Mellin analogue, and normalized-time binning is
//! dilation-invariant by construction (a burst at t=0.92 stays at
//! t=0.92 under stretching).
//!
//! Probe-validated (2026-08-27, /tmp/opencode/mellinprobe): v1
//! log-binned profiles FAILED (bursts spread across dilated sessions
//! shift bins); v2-v4 CDF formulations were dilation-invariant but
//! monotone (cosine dominated by the ramp, families inseparable);
//! v5 per-kind time-histograms PASS the kill criterion:
//!   cross-dilation cosine 0.87-0.99 (same family, 1x/5x/25x)
//!   cross-family cosine 0.29-0.35 (distinct families)
//! The probe ran BEFORE any daemon wiring — the seq-engine lesson.

use serde::{Deserialize, Serialize};

/// Number of normalized-time bins per kind.
pub const BINS: usize = 10;

/// A campaign's scale-invariant signature: per-kind time-histograms
/// concatenated. Dilation-invariant by construction; discriminative
/// because mass location differs between families.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
  pub kinds: Vec<String>,
  pub hist: Vec<f64>,
}

impl Signature {
  pub fn cosine(&self, other: &Signature) -> f64 {
    let a = &self.hist;
    let b = &other.hist;
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    for i in 0..a.len().min(b.len()) {
      dot += a[i] * b[i];
      na += a[i] * a[i];
      nb += b[i] * b[i];
    }
    if na == 0.0 || nb == 0.0 {
      return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
  }
}

/// Compute the signature for a campaign: sessions (each a map of
/// event-kind -> count) in chronological order.
pub fn signature(sessions: &[Vec<(String, u64)>]) -> Signature {
  // collect the kind vocabulary in first-seen order
  let mut kinds: Vec<String> = Vec::new();
  for session in sessions {
    for (kind, _) in session {
      if !kinds.iter().any(|k| k == kind) {
        kinds.push(kind.clone());
      }
    }
  }
  let n = sessions.len().max(1) as f64;
  let mut hist = vec![0.0; kinds.len() * BINS];
  for (i, session) in sessions.iter().enumerate() {
    let t = (i as f64 + 0.5) / n;
    let bin = ((t * BINS as f64) as usize).min(BINS - 1);
    for (kind, count) in session {
      let Some(k) = kinds.iter().position(|x| x == kind) else {
        continue;
      };
      hist[k * BINS + bin] += *count as f64;
    }
  }
  // normalize per kind (fraction of that kind's mass per bin)
  for k in 0..kinds.len() {
    let total: f64 = hist[k * BINS..(k + 1) * BINS].iter().sum();
    if total > 0.0 {
      for h in hist[k * BINS..(k + 1) * BINS].iter_mut() {
        *h /= total;
      }
    }
  }
  Signature { kinds, hist }
}

/// Match a reference signature against historical signatures.
/// Returns (index, cosine) of the best match above the threshold.
pub fn match_against(
  reference: &Signature,
  history: &[Signature],
  threshold: f64,
) -> Option<(usize, f64)> {
  history
    .iter()
    .enumerate()
    .map(|(i, s)| (i, reference.cosine(s)))
    .filter(|(_, c)| *c >= threshold)
    .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn session(kinds: &[(&str, u64)]) -> Vec<(String, u64)> {
    kinds.iter().map(|(k, v)| (k.to_string(), *v)).collect()
  }

  fn probe_campaign() -> Vec<Vec<(String, u64)>> {
    // probe-exfil: slow ramp of probe events, then a burst
    let mut out = Vec::new();
    for i in 0..12 {
      out.push(session(&[("probe", (i as u64) * 2), ("exfil", if i == 11 { 200 } else { 0 })]));
    }
    out
  }

  fn poison_campaign() -> Vec<Vec<(String, u64)>> {
    let mut out = Vec::new();
    for i in 0..12 {
      out.push(session(&[("edit", if i == 6 { 150 } else { 5 }), ("config", (i as u64) % 3)]));
    }
    out
  }

  fn dilate(campaign: &[Vec<(String, u64)>], k: usize) -> Vec<Vec<(String, u64)>> {
    let mut out = Vec::new();
    for session in campaign {
      for _ in 0..k {
        out.push(
          session
            .iter()
            .map(|(kind, count)| (kind.clone(), count.div_ceil(k as u64)))
            .collect(),
        );
      }
    }
    out
  }

  #[test]
  fn cross_dilation_similarity_above_0_8() {
    let probe = probe_campaign();
    let s1 = signature(&probe);
    for k in [5usize, 25] {
      let sk = signature(&dilate(&probe, k));
      assert!(s1.cosine(&sk) > 0.8, "1x vs {k}x must be > 0.8, got {}", s1.cosine(&sk));
    }
  }

  #[test]
  fn cross_family_similarity_below_0_5() {
    let probe = signature(&probe_campaign());
    let poison = signature(&poison_campaign());
    assert!(probe.cosine(&poison) < 0.5, "distinct families must be < 0.5, got {}", probe.cosine(&poison));
  }

  #[test]
  fn match_finds_best_above_threshold() {
    let probe = signature(&probe_campaign());
    let poison = signature(&poison_campaign());
    let history = vec![poison.clone(), probe.clone()];
    let (idx, c) = match_against(&probe, &history, 0.8).expect("match");
    assert_eq!(idx, 1);
    assert!(c > 0.8);
  }

  #[test]
  fn empty_campaign_signature_is_zero() {
    let s = signature(&[]);
    assert!(s.hist.is_empty());
  }
}
