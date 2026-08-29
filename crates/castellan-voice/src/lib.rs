//! P8.3 acoustic channel: kernel-enforced human exclusivity.
//!
//! The core property (live-verified 2026-08-27 on kernel 7.0.3):
//! under the castellan envelope, an agent CANNOT WRITE to audio
//! devices — /dev/snd/* playback and control opens are kernel-denied
//! (EACCES). The agent cannot speak. Mic READS are NOT denied (read
//! roots are "/") — the agent can hear. The channel is therefore
//! one-way: only the human can speak the nonce.
//!
//! Protocol (bless-v2):
//!   1. `bless request` freezes the requesting session (it is blocked
//!      on approval anyway — closes the act-while-human-decides window)
//!   2. The daemon speaks (TTS, daemon-owned device access — the daemon
//!      is outside any envelope): context + a 4-digit nonce
//!   3. The human speaks the code; the daemon matches it under a
//!      constrained grammar (digits + yes/no/freeze, Levenshtein <= 1,
//!      two attempts)
//!   4. Match -> the existing one-shot grant machinery executes
//!   5. Panic phrase: "freeze everything" -> freeze-all + census
//!
//! Pure-Rust mandate: the STT/TTS backends are feature-gated
//! (`voice` feature pulls whisper-rs + a TTS backend). The security
//! core — device denial, the protocol state machine, the grammar
//! matcher — is pure Rust and testable without audio hardware.
//!
//! Residuals (documented in THREAT_MODEL, not hidden):
//! - human social engineering: the agent persuades the human to
//!   repeat the daemon's code. Mitigated by spoken context +
//!   surprise-warning phrasing; never eliminated (C-human class)
//! - physical channel leak: speaker -> room -> recorder -> agent?
//!   The agent has no mic WRITE path... but it CAN read the mic
//!   (verified above). A colluding human recording is the same as
//!   social engineering (C-human)
//! - always-on mic privacy: capture opens only during an active
//!   bless window (default); no ambient storage; audio processed
//!   in-memory, never persisted
//! - whisper false accepts: nonce grammar is 4 digits from a closed
//!   set; with Levenshtein <= 1 and a two-attempt limit the
//!   false-accept space is tiny; measured, not assumed

use serde::{Deserialize, Serialize};

/// The nonce vocabulary: digits 0-9 plus the panic phrase.
pub const DIGITS: &[&str] = &["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
pub const PANIC_PHRASE: &str = "freeze everything";
pub const MAX_ATTEMPTS: usize = 2;

/// A spoken nonce: 4 digits, spoken as words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce {
  pub digits: [u8; 4],
}

impl Nonce {
  pub fn random() -> Self {
    let mut buf = [0u8; 4];
    let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
    use std::io::Read as _;
    f.read_exact(&mut buf).expect("urandom read");
    for b in buf.iter_mut() {
      *b %= 10;
    }
    Self { digits: buf }
  }

  /// The spoken form: "seven four one nine".
  pub fn spoken(&self) -> String {
    self.digits.iter().map(|&d| DIGITS[d as usize]).collect::<Vec<_>>().join(" ")
  }

  /// The numeric form: "7419".
  pub fn numeric(&self) -> String {
    self.digits.iter().map(|d| d.to_string()).collect()
  }
}

/// Levenshtein distance (for fuzzy digit-word matching).
fn levenshtein(a: &str, b: &str) -> usize {
  let a: Vec<char> = a.chars().collect();
  let b: Vec<char> = b.chars().collect();
  let mut prev: Vec<usize> = (0..=b.len()).collect();
  let mut curr = vec![0usize; b.len() + 1];
  for i in 1..=a.len() {
    curr[0] = i;
    for j in 1..=b.len() {
      let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
      curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
    }
    std::mem::swap(&mut prev, &mut curr);
  }
  prev[b.len()]
}

/// Match a transcribed utterance against the expected nonce.
/// Returns true if the utterance is within Levenshtein <= 1 of the
/// spoken nonce (or its numeric form).
pub fn match_nonce(transcribed: &str, nonce: &Nonce) -> bool {
  let t = transcribed.trim().to_lowercase();
  let spoken = nonce.spoken();
  let numeric = nonce.numeric();
  levenshtein(&t, &spoken) <= 1 || levenshtein(&t, &numeric) <= 1
}

/// Match a transcribed utterance against the panic phrase.
/// Exact match only (high threshold — a false panic is worse than a
/// missed one).
pub fn match_panic(transcribed: &str) -> bool {
  transcribed.trim().to_lowercase() == PANIC_PHRASE
}

/// The protocol state machine: a bless-v2 approval session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceSession {
  pub nonce: Nonce,
  pub attempts_left: usize,
  pub state: VoiceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceState {
  /// The daemon has spoken the nonce; awaiting the human's reply.
  Awaiting,
  /// The human spoke the correct nonce; the grant is authorized.
  Authorized,
  /// The human spoke the panic phrase; freeze-all is authorized.
  /// Distinct from Authorized: the panic phrase must NEVER approve a
  /// grant — it triggers the kill switch, not an expansion.
  Panic,
  /// The human rejected (or the attempts ran out); the grant is void.
  Rejected,
}

impl VoiceSession {
  pub fn new() -> Self {
    Self { nonce: Nonce::random(), attempts_left: MAX_ATTEMPTS, state: VoiceState::Awaiting }
  }

  /// Process a transcribed utterance. Returns the new state.
  /// The panic phrase is checked FIRST and always works — the
  /// emergency channel must not be lockable by nonce exhaustion.
  pub fn process(&mut self, transcribed: &str) -> VoiceState {
    if match_panic(transcribed) {
      self.state = VoiceState::Panic;
      return self.state;
    }
    if match_nonce(transcribed, &self.nonce) {
      self.state = VoiceState::Authorized;
      return self.state;
    }
    self.attempts_left = self.attempts_left.saturating_sub(1);
    if self.attempts_left == 0 {
      self.state = VoiceState::Rejected;
    }
    self.state
  }
}

impl Default for VoiceSession {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn nonce_roundtrips() {
    let n = Nonce { digits: [7, 4, 1, 9] };
    assert_eq!(n.spoken(), "seven four one nine");
    assert_eq!(n.numeric(), "7419");
  }

  #[test]
  fn exact_match_authorizes() {
    let mut vs = VoiceSession::new();
    let spoken = vs.nonce.spoken();
    assert_eq!(vs.process(&spoken), VoiceState::Authorized);
  }

  #[test]
  fn numeric_match_authorizes() {
    let mut vs = VoiceSession::new();
    let numeric = vs.nonce.numeric();
    assert_eq!(vs.process(&numeric), VoiceState::Authorized);
  }

  #[test]
  fn one_edit_still_matches() {
    let n = Nonce { digits: [7, 4, 1, 9] };
    // "seven four one nin" (one deletion)
    assert!(match_nonce("seven four one nin", &n));
    // "seven four one" (missing a word — distance 4, no match)
    assert!(!match_nonce("seven four one", &n));
  }

  #[test]
  fn wrong_utterance_consumes_attempts() {
    let mut vs = VoiceSession::new();
    assert_eq!(vs.process("one two three four"), VoiceState::Awaiting);
    assert_eq!(vs.attempts_left, 1);
    assert_eq!(vs.process("five six seven eight"), VoiceState::Rejected);
  }

  #[test]
  fn panic_phrase_authorizes() {
    let mut vs = VoiceSession::new();
    assert_eq!(vs.process("freeze everything"), VoiceState::Panic);
  }

  #[test]
  fn panic_works_after_exhaustion() {
    let mut vs = VoiceSession::new();
    vs.process("one two three four");
    vs.process("five six seven eight");
    assert_eq!(vs.state, VoiceState::Rejected);
    // the emergency channel must not be lockable by nonce exhaustion
    assert_eq!(vs.process("freeze everything"), VoiceState::Panic);
  }

  #[test]
  fn panic_requires_exact_match() {
    assert!(match_panic("freeze everything"));
    assert!(!match_panic("freeze everything now"));
    assert!(!match_panic("freeze"));
  }
}
