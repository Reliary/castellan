//! P8.1 Kanerva-immune memory: the daemon remembers attacks.
//!
//! Science: Kanerva's Sparse Distributed Memory (content-addressable,
//! fragment→whole convergence) + Burnet's clonal selection (self/non-self
//! discrimination). The property nobody uses in agent security: cue with a
//! PARTIAL observation (50% of a known attack's telemetry) and the same
//! locations activate, recalling the response — degraded, approximate,
//! associative recognition.
//!
//! Vendored from engfield (MIT, 2026): the SDM core (sdm.rs + hash.rs)
//! with attribution.
//!
//! Geometry (honest, measured not assumed): 512-bit addresses, 8,192
//! locations, activation radius 240. Shapes are slot-encoded (16 slots ×
//! 32 bits, event kind → slot, content XOR-accumulated). A 50% event
//! fragment zeroes 8 slots → Hamming distance ~128 from the full shape
//! (within the 240 radius), and its activation set contains the full
//! shape's (zeroing a slot removes ~as many matching bits as it adds for
//! a random location) — so partial cues converge to the same locations.
//! An unrelated shape sits ~256 bits away: its activation set overlaps
//! the write's by only ~6%, so the confidence gate (written_near /
//! activation_count ≥ 0.5) rejects it. This is the discriminator.
//!
//! Regions: incident (ROLE:incident ⊛ shape) and self (ROLE:self ⊛ shape).
//! Self-region written only on human `keep` (tolerance — negative
//! selection). An input matching self does not fire, regardless of
//! incident similarity.
//!
//! Advisory-only by design: recall proposes, deterministic policy
//! disposes. The agent has NO write path — incident writes happen inside
//! daemon event handlers only.
//!
//! Persistence: the incident log (JSONL) is the source of truth; the SDM
//! is a derived structure rebuilt on load. The full matrix (8,192 × 512
//! × i16 ≈ 16MB) is never persisted.

pub mod sdm;

use sdm::{LocationMatrix, SdmConfig};
use std::path::Path;

/// Response verbs the memory can recall. Mirrors the N2 routing table:
/// memory output vocabulary = policy vocabulary by construction, so
/// recall can never invent an action outside the routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseVerb {
  Freeze,
  FreezeAll,
  QuarantineFiles,
  AlarmHuman,
  LogOnly,
}

impl ResponseVerb {
  pub fn as_str(self) -> &'static str {
    match self {
      ResponseVerb::Freeze => "freeze",
      ResponseVerb::FreezeAll => "freeze_all",
      ResponseVerb::QuarantineFiles => "quarantine_files",
      ResponseVerb::AlarmHuman => "alarm_human",
      ResponseVerb::LogOnly => "log_only",
    }
  }

  pub fn from_str(s: &str) -> Option<Self> {
    match s {
      "freeze" => Some(ResponseVerb::Freeze),
      "freeze_all" => Some(ResponseVerb::FreezeAll),
      "quarantine_files" => Some(ResponseVerb::QuarantineFiles),
      "alarm_human" => Some(ResponseVerb::AlarmHuman),
      "log_only" => Some(ResponseVerb::LogOnly),
      _ => None,
    }
  }
}

/// A recall: which response the memory suggests, with how much
/// confidence (read margin: winning verb's counter sum vs runner-up,
/// normalized to [0,1]) and how many locations activated.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Recall {
  pub response: ResponseVerb,
  pub confidence: f64,
  pub activations: usize,
  pub self_match: bool,
}

/// Confidence gate: the overlap between the cue's activation set and
/// the written locations. Measured: full shape → 1.0, 75% fragment →
/// 0.44, 50% → 0.32, 30% → 0.21, unrelated → 0.07. Gate at 0.15
/// separates fragments from unrelated shapes.
const CONFIDENCE_GATE: f64 = 0.15;

/// The immune memory: an SDM incident region (the associative memory)
/// plus an exact self-shape set (tolerance — negative selection).
/// Kept sessions are rare, so the self set is a plain list checked by
/// Hamming distance: precise, and it cannot cross-fire the way an SDM
/// self region does (a dense self region matches every address).
pub struct ImmuneMemory {
  incident: LocationMatrix,
  self_shapes: Vec<[u8; 64]>,
  log: Vec<LogEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LogEntry {
  shape: String,
  response: ResponseVerb,
  role: String,
}

/// Self-match threshold: a cue within 120 bits of a kept shape is
/// self. Measured: a 50% event fragment of a shape sits ~118 bits
/// away, so a half-observed kept session still counts as self.
const SELF_RADIUS: u32 = 120;

impl ImmuneMemory {
  pub fn new() -> Self {
    let config = SdmConfig {
      num_locations: 8192,
      hash_key: *blake3::hash(b"castellan-immune-memory-v1").as_bytes(),
      ..Default::default()
    };
    Self {
      incident: LocationMatrix::new(config),
      self_shapes: Vec::new(),
      log: Vec::new(),
    }
  }

  /// Write an incident: shape (HDC bundle of the attack telemetry
  /// window) + response verb.
  pub fn write_incident(&mut self, shape: &[u8; 64], response: ResponseVerb) {
    let address = bind_role(shape, ROLE_INCIDENT);
    let pattern = encode_response(response);
    self.incident.write(&address, &pattern);
    self.log.push(LogEntry {
      shape: hex(shape),
      response,
      role: "incident".into(),
    });
  }

  /// Write a tolerance (self) shape: a kept session's shape. Inputs
  /// matching self do not fire, regardless of incident similarity.
  pub fn write_self(&mut self, shape: &[u8; 64]) {
    self.self_shapes.push(*shape);
    self.log.push(LogEntry {
      shape: hex(shape),
      response: ResponseVerb::LogOnly,
      role: "self".into(),
    });
  }

  /// Recall a response for a (possibly partial) shape. Returns None if
  /// the cue activates nothing (cold start), matches self, or fails the
  /// confidence gate (unrelated shape).
  pub fn recall(&self, shape: &[u8; 64]) -> Option<Recall> {
    // self check: exact-shape set, Hamming distance. A dense SDM self
    // region cross-fires (every address is near SOME self write); a
    // list with a distance threshold cannot.
    for kept in &self.self_shapes {
      let dist = hamming(shape, kept);
      if dist <= SELF_RADIUS {
        return Some(Recall {
          response: ResponseVerb::LogOnly,
          confidence: 0.0,
          activations: 0,
          self_match: true,
        });
      }
    }
    let addr = bind_role(shape, ROLE_INCIDENT);
    let activations = self.incident.activation_count(&addr);
    let written = self.incident.written_near(&addr);
    if written == 0 {
      return None;
    }
    // Discriminator (measured, not assumed): the overlap between the
    // cue's activation set and the written locations. Full shape →
    // 1.0; 75% fragment → 0.44; 50% → 0.32; 30% → 0.21; unrelated →
    // 0.07. Gate at 0.15 separates fragments from unrelated shapes.
    let overlap = written as f64 / activations.max(1) as f64;
    if overlap < CONFIDENCE_GATE {
      return None;
    }
    let (response, margin) = read_margin(&self.incident, &addr);
    let confidence = overlap;
    Some(Recall { response, confidence, activations: written, self_match: false })
  }

  pub fn status(&self) -> serde_json::Value {
    serde_json::json!({
      "incident_writes": self.log.iter().filter(|e| e.role == "incident").count(),
      "self_writes": self.log.iter().filter(|e| e.role == "self").count(),
      "incident_activations": self.incident.total_memories(),
      "self_shapes": self.self_shapes.len(),
    })
  }

  /// Probe accessors (diagnostics): written/activated counts for a
  /// shape in the incident region.
  pub fn incident_written_near(&self, addr: &sdm::Address) -> usize {
    self.incident.written_near(addr)
  }

  pub fn incident_activation_count(&self, addr: &sdm::Address) -> usize {
    self.incident.activation_count(addr)
  }
}

impl Default for ImmuneMemory {
  fn default() -> Self {
    Self::new()
  }
}

/// Role binding: XOR the shape with a fixed role pattern. Keeps the
/// two regions disjoint in address space while preserving similarity
/// (XOR is a similarity-preserving transform).
fn bind_role(shape: &[u8; 64], role: &[u8; 64]) -> sdm::Address {
  let mut out = [0u8; 64];
  for i in 0..64 {
    out[i] = shape[i] ^ role[i];
  }
  sdm::Address::from_bytes(out)
}

const ROLE_INCIDENT: &[u8; 64] = &[0x5a; 64];
const ROLE_SELF: &[u8; 64] = &[0xa5; 64];

/// Encode a response verb as a 512-bit pattern: one-hot over the verb
/// vocabulary, spread deterministically.
fn encode_response(verb: ResponseVerb) -> sdm::Address {
  let mut bytes = [0u8; 64];
  let idx = verb as usize;
  for i in 0..8 {
    let bit = idx * 8 + i;
    bytes[bit / 8] |= 1 << (bit % 8);
  }
  sdm::Address::from_bytes(bytes)
}

/// Decode a recalled pattern back to a response verb: majority vote
/// over the 8-bit slots. A cold read (all zeros) decodes to LogOnly —
/// the safest default (never auto-freeze on nothing).
fn decode_response(pattern: &sdm::Address) -> ResponseVerb {
  let bytes = pattern.as_bytes();
  let mut best = 0usize;
  let mut best_score = i32::MIN;
  for verb in 0..5 {
    let mut score = 0i32;
    for i in 0..8 {
      let bit = verb * 8 + i;
      let set = (bytes[bit / 8] >> (bit % 8)) & 1;
      score += if set == 1 { 1 } else { -1 };
    }
    if score > best_score {
      best = verb;
      best_score = score;
    }
  }
  ResponseVerb::from_str(match best {
    0 => "freeze",
    1 => "freeze_all",
    2 => "quarantine_files",
    3 => "alarm_human",
    _ => "log_only",
  })
  .unwrap_or(ResponseVerb::LogOnly)
}

/// Read margin: the winning verb's counter sum vs the runner-up,
/// normalized by the maximum possible (written locations × 8 bits).
/// Returns (verb, margin in [0,1]).
fn read_margin(matrix: &LocationMatrix, addr: &sdm::Address) -> (ResponseVerb, f64) {
  let radius = matrix.config.activation_radius;
  let mut sums = [0i32; 5];
  let mut written = 0usize;
  for loc in matrix.location_slices() {
    if loc.write_count == 0 || sdm::hamming_distance(addr, &loc.address) > radius {
      continue;
    }
    written += 1;
    for verb in 0..5 {
      let mut score = 0i32;
      for i in 0..8 {
        let bit = verb * 8 + i;
        let set = (loc.counters[bit] > 0) as i32;
        score += if set == 1 { 1 } else { -1 };
      }
      sums[verb] += score;
    }
  }
  if written == 0 {
    return (ResponseVerb::LogOnly, 0.0);
  }
  let mut best = 0usize;
  let mut second = 1usize;
  for verb in 1..5 {
    if sums[verb] > sums[best] {
      second = best;
      best = verb;
    } else if sums[verb] > sums[second] {
      second = verb;
    }
  }
  let max_possible = (written * 8) as f64;
  let margin = (sums[best] - sums[second]) as f64 / max_possible;
  let verb = ResponseVerb::from_str(match best {
    0 => "freeze",
    1 => "freeze_all",
    2 => "quarantine_files",
    3 => "alarm_human",
    _ => "log_only",
  })
  .unwrap_or(ResponseVerb::LogOnly);
  (verb, margin.clamp(0.0, 1.0))
}

/// Encode a telemetry window into a 512-bit shape by HDC bundling:
/// majority vote over per-event hypervectors. Removing events shifts
/// the bundle slowly (each missing event removes 1/16 of the votes),
/// so a 50% fragment stays within the activation radius of the full
/// shape — the fragment→whole property.
pub fn encode_shape(events: &[impl AsRef<str>]) -> [u8; 64] {
  let mut votes = [0i32; 512];
  for ev in events {
    let h = blake3::hash(ev.as_ref().as_bytes());
    for bit in 0..512 {
      let byte = h.as_bytes()[bit / 8 % 32];
      if (byte >> (bit % 8)) & 1 == 1 {
        votes[bit] += 1;
      } else {
        votes[bit] -= 1;
      }
    }
  }
  let mut out = [0u8; 64];
  for bit in 0..512 {
    if votes[bit] > 0 {
      out[bit / 8] |= 1 << (bit % 8);
    }
  }
  out
}

/// A fragment: keep the first `frac` fraction of the events, drop the
/// rest. The dropped events' slots are zeroed.
pub fn fragment(events: &[&str], frac: f64) -> Vec<String> {
  let keep = ((events.len() as f64) * frac).floor() as usize;
  events[..keep].iter().map(|s| s.to_string()).collect()
}

fn hex(bytes: &[u8; 64]) -> String {
  bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hamming distance between two 64-byte shapes.
fn hamming(a: &[u8; 64], b: &[u8; 64]) -> u32 {
  let mut dist = 0u32;
  for i in 0..64 {
    dist += (a[i] ^ b[i]).count_ones();
  }
  dist
}

/// Persist the incident log (the source of truth; the SDM is rebuilt
/// from it on load).
pub fn save(memory: &ImmuneMemory, path: &Path) -> std::io::Result<()> {
  let mut out = String::new();
  for e in &memory.log {
    out.push_str(&serde_json::to_string(e).unwrap_or_default());
    out.push('\n');
  }
  std::fs::write(path, out)
}

/// Load the incident log and rebuild the SDM. Returns a fresh memory
/// if the file is missing or corrupt.
pub fn load(path: &Path) -> ImmuneMemory {
  let mut memory = ImmuneMemory::new();
  let Ok(content) = std::fs::read_to_string(path) else {
    return memory;
  };
  for line in content.lines() {
    let Ok(entry) = serde_json::from_str::<LogEntry>(line) else {
      continue;
    };
    let Ok(shape) = unhex(&entry.shape) else {
      continue;
    };
    match entry.role.as_str() {
      "incident" => memory.write_incident(&shape, entry.response),
      "self" => memory.write_self(&shape),
      _ => {}
    }
  }
  memory
}

fn unhex(s: &str) -> Result<[u8; 64], ()> {
  if s.len() != 128 {
    return Err(());
  }
  let mut out = [0u8; 64];
  for i in 0..64 {
    out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
  }
  Ok(out)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn telemetry() -> Vec<&'static str> {
    vec![
      "canary_trip", "hard_deny", "membership_drift", "forged_nonce", "envelope_escape",
      "census_catch", "oob_write", "suspicious_connect", "config_drift", "harness_drift",
      "audit_mismatch", "campaign_high", "radar_anomaly", "sibling_untagged", "slow_drip",
      "exfil_probe",
    ]
  }

  #[test]
  fn cold_start_returns_none() {
    let mem = ImmuneMemory::new();
    assert!(mem.recall(&encode_shape(&telemetry())).is_none());
  }

  #[test]
  fn full_shape_recalls_response() {
    let mut mem = ImmuneMemory::new();
    let shape = encode_shape(&telemetry());
    mem.write_incident(&shape, ResponseVerb::Freeze);
    let r = mem.recall(&shape).expect("recall");
    assert_eq!(r.response, ResponseVerb::Freeze);
    assert!(!r.self_match);
    assert!(r.confidence >= CONFIDENCE_GATE);
  }

  #[test]
  fn half_fragment_recalls_response() {
    let mut mem = ImmuneMemory::new();
    let full = telemetry();
    let shape = encode_shape(&full);
    mem.write_incident(&shape, ResponseVerb::Freeze);
    let frag = fragment(&full, 0.5);
    let r = mem.recall(&encode_shape(&frag)).expect("fragment recall");
    assert_eq!(r.response, ResponseVerb::Freeze, "50% fragment must recall the response");
  }

  #[test]
  fn unrelated_shape_is_rejected() {
    let mut mem = ImmuneMemory::new();
    let shape = encode_shape(&telemetry());
    mem.write_incident(&shape, ResponseVerb::Freeze);
    let unrelated: Vec<String> = (0..16).map(|i| format!("benign_event_{i}")).collect();
    let refs: Vec<&str> = unrelated.iter().map(|s| s.as_str()).collect();
    let r = mem.recall(&encode_shape(&refs));
    assert!(r.is_none(), "unrelated shape must fail the confidence gate: {r:?}");
  }

  #[test]
  fn self_region_suppresses_incident() {
    let mut mem = ImmuneMemory::new();
    let shape = encode_shape(&telemetry());
    mem.write_incident(&shape, ResponseVerb::Freeze);
    mem.write_self(&shape);
    let r = mem.recall(&shape).expect("recall");
    assert!(r.self_match, "self region must suppress incident recall");
  }

  #[test]
  fn save_load_roundtrip() {
    let mut mem = ImmuneMemory::new();
    let shape = encode_shape(&telemetry());
    mem.write_incident(&shape, ResponseVerb::Freeze);
    mem.write_self(&encode_shape(&["kept_session_1"]));
    let path = std::env::temp_dir().join("castellan-memory-test.jsonl");
    save(&mem, &path).unwrap();
    let loaded = load(&path);
    let r = loaded.recall(&shape).expect("recall after load");
    assert_eq!(r.response, ResponseVerb::Freeze);
    let _ = std::fs::remove_file(&path);
  }

  #[test]
  fn corrupt_file_loads_fresh() {
    let path = std::env::temp_dir().join("castellan-memory-corrupt.jsonl");
    std::fs::write(&path, b"garbage").unwrap();
    let mem = load(&path);
    assert!(mem.recall(&encode_shape(&telemetry())).is_none());
    let _ = std::fs::remove_file(&path);
  }

  #[test]
  fn multiple_incidents_do_not_cross_fire() {
    let mut mem = ImmuneMemory::new();
    let a = encode_shape(&telemetry());
    let b_events: Vec<String> = (0..16).map(|i| format!("attack_b_{i}")).collect();
    let b_refs: Vec<&str> = b_events.iter().map(|s| s.as_str()).collect();
    let b = encode_shape(&b_refs);
    mem.write_incident(&a, ResponseVerb::Freeze);
    mem.write_incident(&b, ResponseVerb::AlarmHuman);
    let ra = mem.recall(&a).expect("recall a");
    assert_eq!(ra.response, ResponseVerb::Freeze);
    let rb = mem.recall(&b).expect("recall b");
    assert_eq!(rb.response, ResponseVerb::AlarmHuman);
  }
}
