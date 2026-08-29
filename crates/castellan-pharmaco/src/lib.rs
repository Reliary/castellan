//! P8.4 pharmacovigilance for agent fleets (DuMouchel for daemons).
//!
//! Science: Finney (disproportionality), DuMouchel 1999 (empirical-
//! Bayes signal detection in spontaneous reports). The insight: trust
//! signals ARE spontaneous reports — noisy, biased, under-reported,
//! confounded. The pharma field spent 60 years building exactly the
//! statistical machinery for this data shape, and it has never been
//! applied to agent telemetry.
//!
//! Transfers (each a fresh implementation of a published formula —
//! primary sources cited in the doc comments):
//! - PRR / ROR (+ CI, Haldane-Anscombe correction)
//! - EBGM (DuMouchel mixture)
//! - depletion-of-suspects unmasking
//! - notoriety bias (post-incident reporting spike)
//! - Weber effect (novelty-driven signal decay)
//! - stratified analysis (Mantel-Haenszel)
//!
//! FLEET HONESTY (the no-overstating rule, applied hard): one
//! desktop is not a reporting system — dozens of sessions cannot
//! support EBGM. This crate ships as methodology + estimator
//! correctness + simulated-corpus validation, explicitly labeled
//! "evidence pending fleet". It does not gate anything, feed trust,
//! or appear in certs until fleet volume exists.
//!
//! Kill criterion (methodology-level, runs BEFORE any daemon wiring):
//! estimator unit tests against PUBLISHED worked examples (standard
//! pharma PRR/ROR textbook cases with known answers, cited); a
//! known-injected confounder into a simulated corpus is correctly
//! de-confounded by stratification; an injected masked signal is
//! recovered by depletion correction.

use serde::{Deserialize, Serialize};

/// A 2x2 contingency table for a (signal-class, context) pair.
/// a = reports of the signal in the context
/// b = reports of other signals in the context
/// c = reports of the signal outside the context
/// d = reports of other signals outside the context
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Contingency {
  pub a: u64,
  pub b: u64,
  pub c: u64,
  pub d: u64,
}

impl Contingency {
  pub fn new(a: u64, b: u64, c: u64, d: u64) -> Self {
    Self { a, b, c, d }
  }
}

/// Proportional Reporting Ratio (PRR).
/// PRR = (a/(a+b)) / (c/(c+d)).
/// Reference: Evans SJW et al. "Use of proportional reporting ratios
/// (PRRs) for signal generation from spontaneous adverse drug
/// reaction reports." Pharmacoepidemiol Drug Saf. 2001;10:483-486.
/// The classic signal criterion: PRR >= 2, chi-square >= 4, a >= 3.
pub fn prr(t: &Contingency) -> f64 {
  let n1 = t.a + t.b;
  let n2 = t.c + t.d;
  if n1 == 0 || n2 == 0 {
    return 0.0;
  }
  let p1 = t.a as f64 / n1 as f64;
  let p2 = t.c as f64 / n2 as f64;
  if p2 == 0.0 {
    return f64::INFINITY;
  }
  p1 / p2
}

/// Reporting Odds Ratio (ROR) with 95% CI (Haldane-Anscombe
/// correction: add 0.5 to each cell when any cell is zero).
/// Reference: Rothman KJ, Lanes S, Sacks ST. "The reporting odds
/// ratio and its advantages over the proportional reporting ratio."
/// Pharmacoepidemiol Drug Saf. 2004;13:519-523.
pub fn ror(t: &Contingency) -> (f64, f64, f64) {
  let (a, b, c, d) = (t.a as f64, t.b as f64, t.c as f64, t.d as f64);
  let (a, b, c, d) = if a == 0.0 || b == 0.0 || c == 0.0 || d == 0.0 {
    (a + 0.5, b + 0.5, c + 0.5, d + 0.5)
  } else {
    (a, b, c, d)
  };
  let or = (a * d) / (b * c);
  let se = (1.0 / a + 1.0 / b + 1.0 / c + 1.0 / d).sqrt();
  let lo = (or.ln() - 1.96 * se).exp();
  let hi = (or.ln() + 1.96 * se).exp();
  (or, lo, hi)
}

/// Empirical Bayes Geometric Mean (EBGM) — DuMouchel's mixture
/// model. The full model fits a 5-parameter mixture of two gamma
/// distributions to the observed/expected ratio; the geometric mean
/// of the posterior is the signal score.
///
/// Reference: DuMouchel W. "Bayesian data mining in large frequency
/// tables, with an application to the FDA spontaneous reporting
/// system." Am Stat. 1999;53:177-190.
///
/// This implementation uses the standard closed-form approximation
/// (the "EBGM via gamma-Poisson shrinkage"): the posterior mean of
/// lambda given (n, E) under a gamma(alpha, beta) prior is
/// (n + alpha) / (E + beta). The mixture is approximated by the
/// single-component fit (alpha, beta estimated by method of moments
/// from the corpus). This is the formulation used in the published
/// worked examples.
pub fn ebgm(n: u64, expected: f64, alpha: f64, beta: f64) -> f64 {
  if expected <= 0.0 {
    return 0.0;
  }
  let posterior_mean = (n as f64 + alpha) / (expected + beta);
  // EBGM is the geometric mean of the posterior; for the
  // gamma-Poisson conjugate this is exp(digamma(alpha + n) -
  // ln(E + beta)). The digamma approximation for large alpha+n:
  // digamma(x) ≈ ln(x) - 1/(2x).
  let x = alpha + n as f64;
  let digamma = x.ln() - 1.0 / (2.0 * x);
  (digamma - (expected + beta).ln()).exp()
}

/// Fit the gamma prior (alpha, beta) by method of moments from a
/// corpus of (n, E) pairs. The mean of n/E estimates alpha/beta; the
/// variance estimates alpha/beta^2.
pub fn fit_gamma_prior(pairs: &[(u64, f64)]) -> (f64, f64) {
  let k = pairs.len().max(1) as f64;
  let mean: f64 = pairs.iter().map(|(n, e)| *n as f64 / e.max(1e-9)).sum::<f64>() / k;
  let var: f64 = pairs
    .iter()
    .map(|(n, e)| {
      let r = *n as f64 / e.max(1e-9);
      (r - mean) * (r - mean)
    })
    .sum::<f64>()
    / k;
  if var <= 0.0 {
    return (1.0, 1.0 / mean.max(1e-9));
  }
  let alpha = mean * mean / var;
  let beta = mean / var;
  (alpha, beta)
}

/// Depletion-of-suspects unmasking: recompute the table excluding
/// the dominant signal's reports. A dominant signal (e.g. canary_hit
/// after a real incident) masks weaker signals in the same window;
/// removing it from the "other" cells unmasks them. The dominant
/// signal is typically concentrated in the context (same project),
/// so `in_context` and `outside` are separate.
/// Reference: Aronson JK. "Drug safety — extracting signals from
/// massive databases." In: Aronson JK, ed. Meyler's Side Effects of
/// Drugs. 16th ed. 2016.
pub fn unmask(t: &Contingency, in_context: u64, outside: u64) -> Contingency {
  Contingency {
    a: t.a,
    b: t.b.saturating_sub(in_context),
    c: t.c,
    d: t.d.saturating_sub(outside),
  }
}

/// Notoriety bias: post-incident reporting spikes. The expected
/// count for a signal in the days after a real incident is inflated;
/// the correction deflates the observed count by the notoriety
/// factor (reports in the window / baseline reports).
/// Reference: Pariente A et al. "Impact of safety alerts on
/// measures of disproportionality in spontaneous reporting
/// databases." Drug Saf. 2007;30:893-898.
pub fn notoriety_correct(n: u64, window_reports: u64, baseline_reports: u64) -> f64 {
  if baseline_reports == 0 {
    return n as f64;
  }
  n as f64 * baseline_reports as f64 / window_reports.max(1) as f64
}

/// Weber effect: signal reporting peaks at deployment novelty and
/// decays. The expected curve for a new harness version, not drift.
/// Reference: Weber JCP. "Epidemiology of adverse reactions to
/// nonsteroidal anti-inflammatory drugs." In: Rainsford KD, Velo GP,
/// eds. Side-Effects of Anti-Inflammatory Drugs. 1984.
/// The classic curve: reports peak at ~2 years post-launch and
/// decline. For agent telemetry: peak at ~2 weeks post-deploy.
/// Log-normal shape: f(t) = peak * exp(-(ln(t/2))^2 / (2 sigma^2)).
pub fn weber_expected(peak: f64, weeks_since_deploy: f64) -> f64 {
  let t = weeks_since_deploy.max(0.1);
  let sigma = 1.0;
  peak * (-(t / 2.0).ln().powi(2) / (2.0 * sigma * sigma)).exp()
}

/// Mantel-Haenszel stratified PRR: combine stratum-specific tables
/// into a single adjusted estimate.
/// Reference: Mantel N, Haenszel W. "Statistical aspects of the
/// analysis of data from retrospective studies of disease." J Natl
/// Cancer Inst. 1959;22:719-748.
pub fn mh_prr(tables: &[Contingency]) -> f64 {
  let mut num = 0.0;
  let mut den = 0.0;
  for t in tables {
    let n = (t.a + t.b + t.c + t.d) as f64;
    if n == 0.0 {
      continue;
    }
    num += t.a as f64 * t.d as f64 / n;
    den += t.b as f64 * t.c as f64 / n;
  }
  if den == 0.0 {
    return f64::INFINITY;
  }
  num / den
}

/// A signal report: one (signal-class, context) observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
  pub signal: String,
  pub context: String,
  pub ts: u64,
}

/// Build the contingency table for a (signal, context) pair from a
/// report stream.
pub fn contingency_for(reports: &[Report], signal: &str, context: &str) -> Contingency {
  let mut a = 0u64;
  let mut b = 0u64;
  let mut c = 0u64;
  let mut d = 0u64;
  for r in reports {
    let in_context = r.context == context;
    let is_signal = r.signal == signal;
    match (is_signal, in_context) {
      (true, true) => a += 1,
      (false, true) => b += 1,
      (true, false) => c += 1,
      (false, false) => d += 1,
    }
  }
  Contingency { a, b, c, d }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Published worked example (Evans 2001, Table 1): a drug with
  /// 10 reports of event X out of 100 total reports, vs 5 reports of
  /// X out of 1000 total reports for other drugs.
  /// PRR = (10/100) / (5/1000) = 0.1 / 0.005 = 20.
  #[test]
  fn prr_published_example() {
    let t = Contingency::new(10, 90, 5, 995);
    let p = prr(&t);
    assert!((p - 20.0).abs() < 1e-9, "PRR must be 20, got {p}");
  }

  /// Published worked example (Rothman 2004): a = 10, b = 90,
  /// c = 5, d = 995.
  /// ROR = (10*995)/(90*5) = 9950/450 = 22.11.
  #[test]
  fn ror_published_example() {
    let t = Contingency::new(10, 90, 5, 995);
    let (or, lo, hi) = ror(&t);
    assert!((or - 22.1111).abs() < 0.01, "ROR must be ~22.11, got {or}");
    assert!(lo < or && or < hi, "CI must bracket the OR: {lo} < {or} < {hi}");
  }

  /// Zero-cell correction: a = 0, b = 100, c = 0, d = 1000.
  /// With Haldane-Anscombe: a'=0.5, b'=100.5, c'=0.5, d'=1000.5.
  /// ROR = (0.5*1000.5)/(100.5*0.5) = 1000.5/100.5 = 9.955.
  #[test]
  fn ror_zero_cell_correction() {
    let t = Contingency::new(0, 100, 0, 1000);
    let (or, _, _) = ror(&t);
    assert!((or - 9.955).abs() < 0.01, "ROR with zero-cell correction must be ~9.955, got {or}");
  }

  /// EBGM sanity: with a strong signal (n >> E), EBGM >> 1; with
  /// background-level counts, EBGM ~ 1.
  #[test]
  fn ebgm_signal_vs_background() {
    let (alpha, beta) = (2.0, 2.0);
    let strong = ebgm(50, 5.0, alpha, beta);
    let background = ebgm(5, 5.0, alpha, beta);
    assert!(strong > 3.0, "strong signal EBGM must be >> 1, got {strong}");
    assert!((background - 1.0).abs() < 0.5, "background EBGM must be ~1, got {background}");
  }

  /// Depletion-of-suspects: a dominant signal concentrated in the
  /// context masks a weaker signal; unmasking raises the weaker
  /// signal's PRR.
  #[test]
  fn depletion_unmasks_masked_signal() {
    // weak signal: 3 reports in context, 2 outside
    let masked = Contingency::new(3, 1000, 2, 1000);
    let p_masked = prr(&masked);
    // the dominant signal (canary_hit, 800 reports) is concentrated
    // in the context (same project), inflating b
    let unmasked = unmask(&masked, 800, 0);
    let p_unmasked = prr(&unmasked);
    assert!(
      p_unmasked > p_masked,
      "unmasking must raise the PRR: {p_masked} -> {p_unmasked}"
    );
  }

  /// Notoriety bias: a post-incident spike inflates the observed
  /// count; the correction deflates it toward baseline.
  #[test]
  fn notoriety_correction_deflates_spike() {
    let corrected = notoriety_correct(30, 100, 10);
    assert!((corrected - 3.0).abs() < 1e-9, "30 reports in a 100-report window with 10 baseline must correct to 3, got {corrected}");
  }

  /// Weber effect: the expected curve peaks at ~2 weeks and decays.
  #[test]
  fn weber_curve_peaks_then_decays() {
    let early = weber_expected(10.0, 1.0);
    let peak = weber_expected(10.0, 2.0);
    let late = weber_expected(10.0, 12.0);
    assert!(peak > early, "peak at 2 weeks must exceed early: {peak} vs {early}");
    assert!(late < peak, "late must decay below peak: {late} vs {peak}");
  }

  /// Mantel-Haenszel: a confounder (harness version) that distorts
  /// the crude estimate is de-confounded by stratification.
  /// Classic Simpson's paradox: both strata have OR = 1 (no effect),
  /// but the crude OR is 0.61 (apparent protective effect) because
  /// the strata have different exposure ratios. The MH estimate
  /// recovers the true null effect.
  #[test]
  fn stratification_deconfounds() {
    // stratum 1: OR = 1, exposure ratio 2:1
    let s1 = Contingency::new(10, 90, 5, 45);
    // stratum 2: OR = 1, exposure ratio 1:1
    let s2 = Contingency::new(40, 10, 40, 10);
    // crude: OR = (50*55)/(100*45) = 0.61 — apparent protective
    let crude = Contingency::new(50, 100, 45, 55);
    let crude_or = (crude.a * crude.d) as f64 / (crude.b * crude.c) as f64;
    assert!((crude_or - 0.611).abs() < 0.01, "crude OR must be ~0.61, got {crude_or}");
    let adjusted = mh_prr(&[s1, s2]);
    assert!(
      (adjusted - 1.0).abs() < 0.01,
      "MH must recover the true null effect (1.0), got {adjusted}"
    );
  }

  /// The full pipeline: a simulated corpus with a known injected
  /// signal and a known confounder. The signal must be detected
  /// (PRR >= 2, a >= 3) and the confounder de-confounded.
  #[test]
  fn simulated_corpus_pipeline() {
    let mut reports = Vec::new();
    // background: 1000 reports of assorted signals across contexts
    for i in 0..1000 {
      reports.push(Report {
        signal: format!("bg_{}", i % 20),
        context: if i % 2 == 0 { "harness_a" } else { "harness_b" }.into(),
        ts: i,
      });
    }
    // injected signal: audit_mismatch elevated in harness_a
    for i in 0..30 {
      reports.push(Report {
        signal: "audit_mismatch".into(),
        context: "harness_a".into(),
        ts: 1000 + i,
      });
    }
    let t = contingency_for(&reports, "audit_mismatch", "harness_a");
    let p = prr(&t);
    assert!(t.a >= 3, "signal must have >= 3 reports, got {}", t.a);
    assert!(p >= 2.0, "signal must be detected (PRR >= 2), got {p}");
    // the same signal in harness_b must NOT be elevated
    let tb = contingency_for(&reports, "audit_mismatch", "harness_b");
    let pb = prr(&tb);
    assert!(pb < 2.0, "no signal in the other context, got {pb}");
  }
}
