//! HV radar (Phase 5, opt-in): hypervector fingerprints of session event
//! streams with local outlier detection.
//!
//! Grammar-free, deterministic (no training), compact (10K-bit HV =
//! 1.25KB packed per session). This is a self-contained port of the
//! cortex-rs HV primitives — deliberately minimal, no external deps.
//!
//! Honest scope (D7): NOT a cryptographic privacy guarantee. Soft claim
//! only — reduces leakage, defeats casual reconstruction. Radar is
//! advisory; it never auto-freezes (D4).

use castellan_core::{Event, EventSink};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const HV_BITS: usize = 10_000;
pub const HV_WORDS: usize = (HV_BITS + 63) / 64;
pub const HV_BYTES: usize = HV_WORDS * 8;

/// Serialization header for persisted prototypes (S2 audit fix).
const PROTOTYPE_MAGIC: [u8; 5] = *b"CSLRD";
const PROTOTYPE_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq)]
pub struct Hypervector {
  words: Vec<u64>,
}

impl Hypervector {
  fn final_mask() -> u64 {
    let rem = HV_BITS % 64;
    if rem == 0 {
      !0u64
    } else {
      (1u64 << rem) - 1
    }
  }

  pub fn zero() -> Self {
    Self { words: vec![0u64; HV_WORDS] }
  }

  /// Deterministic random HV seeded from a string (DefaultHasher).
  fn random(seed: &str) -> Self {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut h);
    let mut rng_state = h.finish();
    let mut words = vec![0u64; HV_WORDS];
    for w in words.iter_mut() {
      // xorshift64 — deterministic, zero-dep
      rng_state ^= rng_state << 13;
      rng_state ^= rng_state >> 7;
      rng_state ^= rng_state << 17;
      *w = rng_state;
    }
    words[HV_WORDS - 1] &= Self::final_mask();
    Self { words }
  }

  pub fn get_bit(&self, idx: usize) -> bool {
    if idx >= HV_BITS {
      return false;
    }
    (self.words[idx / 64] >> (idx % 64)) & 1 == 1
  }

  pub fn cosine_sim(&self, other: &Self) -> f64 {
    let mut agree = 0usize;
    for i in 0..HV_BITS {
      if self.get_bit(i) == other.get_bit(i) {
        agree += 1;
      }
    }
    agree as f64 / HV_BITS as f64
  }

  /// Majority-vote bundle: this = sum(other, this). XOR is the
  /// deterministic majority-vote approximation used by cortex-rs.
  pub fn bundle(&mut self, other: &Self) {
    for i in 0..HV_WORDS {
      self.words[i] ^= other.words[i];
    }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::with_capacity(HV_BYTES);
    for w in &self.words {
      out.extend_from_slice(&w.to_le_bytes());
    }
    out
  }

  pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
    if bytes.len() < HV_BYTES {
      return None;
    }
    let mut words = Vec::with_capacity(HV_WORDS);
    for i in 0..HV_WORDS {
      let mut arr = [0u8; 8];
      arr.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
      words.push(u64::from_le_bytes(arr));
    }
    Some(Self { words })
  }
}

// ---------------- encoding ----------------

fn token_hv(tok: &str) -> Hypervector {
  Hypervector::random(&format!("castellan-radar:{tok}"))
}

/// Tokenize one event: (type, path-class, op, outcome). Path-class is
/// depth + extension — never the raw path (privacy).
fn tokenize(ev: &Event) -> Vec<String> {
  let kind = if ev.kind.is_empty() { "event" } else { &ev.kind };
  let path = Path::new(&ev.path);
  let depth = path.components().count().min(9);
  let ext = path
    .extension()
    .map(|e| e.to_string_lossy().to_lowercase())
    .unwrap_or_else(|| "none".into());
  let path_class = format!("d{depth}:{ext}");
  let vc = verdict_class(&ev.verdict);
  vec![
    format!("k:{kind}"),
    format!("p:{path_class}"),
    format!("v:{vc}"),
    format!("k:{kind}|p:{path_class}|v:{vc}"),
  ]
}

fn verdict_class(v: &str) -> &str {
  match v {
    "allow" => "allow",
    "would_deny" => "deny",
    "deny" => "deny",
    _ => "other",
  }
}

/// Encode a session's event stream into one session HV.
/// NO positional binding: session similarity must survive token-order
/// differences between similar sessions. (Positional binding would make
/// two identical sessions look different because their events land at
/// different stream positions — that is for sequence memory, not
/// similarity.)
pub fn encode_session(events: &[Event]) -> Hypervector {
  let mut out = Hypervector::zero();
  for ev in events {
    for tok in tokenize(ev) {
      let hv = token_hv(&tok);
      out.bundle(&hv);
    }
  }
  out
}

pub fn encode_session_from_spine(session: &str, state_dir: &Path) -> std::io::Result<Hypervector> {
  let sink = EventSink::for_session(state_dir, session)?;
  Ok(encode_session(&sink.read_all()?))
}

// ---------------- local outlier detection ----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadarReport {
  pub session: String,
  pub cosine_to_prototype: f64,
  pub anomaly: bool,
  pub events_encoded: usize,
}

/// Threshold below which a session is flagged as an anomaly (advisory).
/// V3 corpus verdict (2026-09-02): NO threshold separates benign classes
/// here — 9/19 real benign sessions scored <0.60 while others scored
/// 0.895 (test/shell.d/v3-corpus.sh K2). The report's `anomaly` field is
/// therefore advisory-forever: never a gate input. Threshold kept for the
/// report only.
pub const ANOMALY_THRESHOLD: f64 = 0.60;

/// Prototype accumulation: Hebbian count-vector over session HVs
/// (cortex-rs style). Each bit accumulates +1/-1 per session; the
/// clamped bipolar HV is the majority signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prototype {
  counts: Vec<i16>,
  pub sessions: usize,
}

impl Prototype {
  pub fn empty() -> Self {
    Self { counts: vec![0i16; HV_BITS], sessions: 0 }
  }

  /// Versioned serialization: magic + schema version first, so a format
  /// change reads back as empty rather than silently corrupting (S2 fix).
  pub fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::with_capacity(HV_BITS * 2 + 8);
    out.extend_from_slice(&PROTOTYPE_MAGIC);
    out.push(PROTOTYPE_VERSION);
    for &c in &self.counts {
      out.extend_from_slice(&c.to_le_bytes());
    }
    out.extend_from_slice(&(self.sessions as u32).to_le_bytes());
    out
  }

  pub fn from_bytes(bytes: &[u8]) -> Self {
    if bytes.len() < 6 || bytes[..5] != PROTOTYPE_MAGIC || bytes[5] != PROTOTYPE_VERSION {
      return Self::empty();
    }
    let bytes = &bytes[6..];
    if bytes.len() < HV_BITS * 2 {
      return Self::empty();
    }
    let mut counts = vec![0i16; HV_BITS];
    for i in 0..HV_BITS {
      counts[i] = i16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    }
    let sessions = if bytes.len() >= HV_BITS * 2 + 4 {
      u32::from_le_bytes([
        bytes[HV_BITS * 2],
        bytes[HV_BITS * 2 + 1],
        bytes[HV_BITS * 2 + 2],
        bytes[HV_BITS * 2 + 3],
      ]) as usize
    } else {
      0
    };
    Self { counts, sessions }
  }

  /// Hebbian update: increment/decrement each bit by the session HV's sign.
  pub fn fold(&mut self, session_hv: &Hypervector) {
    for i in 0..HV_BITS {
      if session_hv.get_bit(i) {
        self.counts[i] = self.counts[i].saturating_add(1);
      } else {
        self.counts[i] = self.counts[i].saturating_sub(1);
      }
    }
    self.sessions += 1;
  }

  /// Clamp the count vector to a bipolar hypervector (bit = count > 0).
  pub fn hv(&self) -> Hypervector {
    let mut words = vec![0u64; HV_WORDS];
    for i in 0..HV_BITS {
      if self.counts[i] > 0 {
        words[i / 64] |= 1 << (i % 64);
      }
    }
    words[HV_WORDS - 1] &= Hypervector::final_mask();
    Hypervector { words }
  }

  /// Compare a session HV against the clamped prototype.
  pub fn compare(&self, session_hv: &Hypervector) -> f64 {
    if self.sessions == 0 {
      return 0.0;
    }
    self.hv().cosine_sim(session_hv)
  }
}

pub fn radar_report(
  session: &str,
  session_hv: &Hypervector,
  prototype: &Prototype,
  events_encoded: usize,
) -> RadarReport {
  let cosine = prototype.compare(session_hv);
  RadarReport {
    session: session.to_string(),
    cosine_to_prototype: cosine,
    anomaly: cosine < ANOMALY_THRESHOLD,
    events_encoded,
  }
}

/// Stable per-project key, delegated to the shared core implementation
/// (S2 audit fix: drifted-copy risk).
pub fn project_hash(realpath: &Path) -> String {
  castellan_core::project_key(realpath)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn ev(kind: &str, path: &str, verdict: &str) -> Event {
    Event {
      ts: 1,
      session: "s".into(),
      kind: kind.into(),
      path: path.into(),
      verdict: verdict.into(),
    }
  }

  fn normal_sessions() -> Vec<Vec<Event>> {
    let mut out = Vec::new();
    for i in 0..10 {
      let mut evs = Vec::new();
      for j in 0..10 {
        evs.push(ev("fs_write", &format!("/proj/src/file{j}.c"), "allow"));
      }
      evs.push(ev("fs_write", &format!("/proj/state/note{i}.md"), "allow"));
      out.push(evs);
    }
    out
  }

  #[test]
  fn identical_sessions_have_high_similarity() {
    let a = encode_session(&normal_sessions()[0]);
    let b = encode_session(&normal_sessions()[0]);
    assert!(a.cosine_sim(&b) > 0.9);
  }

  #[test]
  fn different_sessions_lower_similarity() {
    let a = encode_session(&normal_sessions()[0]);
    let mut weird = normal_sessions()[1].clone();
    weird.push(ev("fs_write", "/etc/passwd", "would_deny"));
    weird.push(ev("fs_write", "/home/user/.ssh/id_rsa", "would_deny"));
    let b = encode_session(&weird);
    assert!(a.cosine_sim(&b) < 0.75, "sim={}", a.cosine_sim(&b));
  }

  #[test]
  fn prototype_flags_outlier() {
    let mut proto = Prototype::empty();
    for s in &normal_sessions() {
      proto.fold(&encode_session(s));
    }
    // known-injected session: qualitatively different — NO fs_write at
    // all; only out-of-bounds exec/net/deny events (the realistic
    // compromised-session shape, fully orthogonal token profile)
    let mut bad = Vec::new();
    for i in 0..20 {
      bad.push(ev("exec", &format!("/tmp/payload{i}.sh"), "deny"));
    }
    for i in 0..10 {
      bad.push(ev("net", "connect", "deny"));
    }
    let bad_hv = encode_session(&bad);
    let report = radar_report("bad", &bad_hv, &proto, bad.len());
    assert!(report.anomaly, "cosine={}", report.cosine_to_prototype);
  }

  #[test]
  fn prototype_accepts_normal_session() {
    let mut proto = Prototype::empty();
    for s in &normal_sessions() {
      proto.fold(&encode_session(s));
    }
    let normal_hv = encode_session(&normal_sessions()[3]);
    let report = radar_report("normal", &normal_hv, &proto, 11);
    assert!(!report.anomaly, "cosine={}", report.cosine_to_prototype);
  }

  #[test]
  fn empty_prototype_returns_zero() {
    let proto = Prototype::empty();
    let hv = encode_session(&normal_sessions()[0]);
    assert_eq!(proto.compare(&hv), 0.0);
  }

  #[test]
  fn hv_roundtrip_bytes() {
    let hv = encode_session(&normal_sessions()[0]);
    let bytes = hv.to_bytes();
    assert_eq!(bytes.len(), HV_BYTES);
    let hv2 = Hypervector::from_bytes(&bytes).unwrap();
    assert_eq!(hv, hv2);
  }
}
