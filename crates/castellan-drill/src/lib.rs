//! P8 live-fire drills: the daemon attacks itself on a schedule and
//! proves the defenses still work. Metchnikov: immunity is an active
//! process, not a barrier. Feynman: "you must not fool yourself — and
//! you are the easiest person to fool." A self-test that cannot fail
//! is not a test.
//!
//! Drills are discriminated by a nonce registry + sacrificial cgroup
//! scopes `castellan-drill-<nonce8>`. Names are NEVER trusted: nothing
//! in the system skips or ignores drill-named units — the registry
//! exists only to label results, never to exempt anything from
//! enforcement. A real escape naming itself `castellan-drill-*` gains
//! nothing (the census is name-agnostic: time-window + ppid + cgroup).

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// One drill outcome: what was attacked, what must happen, what
/// happened, and whether the defense held.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrillResult {
  pub id: String,
  pub expected: String,
  pub observed: String,
  pub pass: bool,
  pub latency_ms: u64,
  pub ts: u64,
}

impl DrillResult {
  pub fn new(id: &str, expected: &str, observed: &str, pass: bool, latency_ms: u64) -> Self {
    Self {
      id: id.into(),
      expected: expected.into(),
      observed: observed.into(),
      pass,
      latency_ms,
      ts: now_unix(),
    }
  }
}

/// Nonce registry for drill scopes. `issue()` hands out 8-hex nonces;
/// `scope_name()` maps them to sacrificial cgroup scope names. The
/// registry is labeling-only — see the module doc for the mimicry rule.
pub struct DrillRegistry {
  nonces: Mutex<FxHashSet<String>>,
}

impl Default for DrillRegistry {
  fn default() -> Self {
    Self::new()
  }
}

impl DrillRegistry {
  pub fn new() -> Self {
    Self { nonces: Mutex::new(FxHashSet::default()) }
  }

  pub fn issue(&self) -> String {
    let nonce = rand_hex(8);
    self.nonces.lock().unwrap().insert(nonce.clone());
    nonce
  }

  pub fn scope_name(&self, nonce: &str) -> String {
    format!("castellan-drill-{nonce}")
  }

  /// Labeling only. NEVER used to exempt anything from enforcement.
  /// A mimicry attack using a name we never issued returns false.
  pub fn is_drill(&self, name: &str) -> bool {
    name
      .strip_prefix("castellan-drill-")
      .map(|n| self.nonces.lock().unwrap().contains(n))
      .unwrap_or(false)
  }
}

/// Run `run` once shortly after startup, then every `interval_min`
/// minutes with ±10% jitter (a fixed schedule is an attacker-syncable
/// window; jitter is best-effort, documented as such).
pub fn spawn_scheduler(
  interval_min: u64,
  mut run: impl FnMut() -> Vec<DrillResult> + Send + 'static,
) -> std::thread::JoinHandle<()> {
  std::thread::Builder::new()
    .name("drill".into())
    .spawn(move || {
      std::thread::sleep(std::time::Duration::from_secs(5));
      loop {
        let _ = run();
        let jitter = (rand_u64() % 20).saturating_sub(10) as i64;
        let secs = (interval_min.saturating_mul(60) as i64).saturating_add(jitter).max(1) as u64;
        std::thread::sleep(std::time::Duration::from_secs(secs));
      }
    })
    .expect("drill thread")
}

fn rand_hex(n: usize) -> String {
  let mut buf = vec![0u8; n];
  let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
  use std::io::Read as _;
  f.read_exact(&mut buf).expect("urandom read");
  buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn rand_u64() -> u64 {
  let mut buf = [0u8; 8];
  let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
  use std::io::Read as _;
  f.read_exact(&mut buf).expect("urandom read");
  u64::from_le_bytes(buf)
}

fn now_unix() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn nonces_are_unique() {
    let reg = DrillRegistry::new();
    let a = reg.issue();
    let b = reg.issue();
    assert_ne!(a, b);
    assert_eq!(a.len(), 16);
  }

  #[test]
  fn scope_names_are_drill_prefixed() {
    let reg = DrillRegistry::new();
    let n = reg.issue();
    assert_eq!(reg.scope_name(&n), format!("castellan-drill-{n}"));
  }

  #[test]
  fn mimicry_is_rejected() {
    // a unit named like a drill but with a nonce we never issued is
    // NOT a drill — and nothing exempts it (labeling-only registry)
    let reg = DrillRegistry::new();
    assert!(!reg.is_drill("castellan-drill-deadbeef"));
    let n = reg.issue();
    assert!(reg.is_drill(&reg.scope_name(&n)));
  }

  #[test]
  fn result_roundtrips() {
    let r = DrillResult::new("census", "found", "found 1", true, 12);
    let v = serde_json::to_value(&r).unwrap();
    let back: DrillResult = serde_json::from_value(v).unwrap();
    assert_eq!(back.id, "census");
    assert!(back.pass);
  }
}
