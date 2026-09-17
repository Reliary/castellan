//! S2 (chapter 5): ed25519 certificate signing.
//!
//! The signing key is generated in-process at daemon start and never
//! written to disk. The S0 probe (docs/s0-key-extraction-probe.md)
//! established two things that shape this module:
//!
//! 1. A same-uid agent can READ any file the daemon writes (read roots
//!    are `/`), so a persisted key is worthless — it can sign arbitrary
//!    certificates.
//! 2. A memory-only key is still extractable via coredump: a same-uid
//!    process can `SIGABRT` the daemon and `systemd-coredump` writes the
//!    full memory image. The closure is `PR_SET_DUMPABLE=0` +
//!    `RLIMIT_CORE=0`, verified to produce no core.
//!
//! Honest scope: the key is per-boot (a persisted key would be readable;
//! a restart invalidates nothing about integrity, but the public key is
//! embedded in each certificate so pinning is per-boot). What a
//! certificate proves is integrity and provenance WITHIN a boot against
//! cross-machine fabrication and post-hoc edits by another user — not
//! non-repudiation against a same-uid adversary with kernel-level
//! access. Residual risks are in THREAT_MODEL.md (C9/C32).

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

/// A detached signature over a certificate's canonical bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSignature {
  /// hex public key (32 bytes). Embedded so a verifier can pin it
  /// without a separate trust store; `verify` also checks the caller's
  /// expected key when one is supplied.
  pub public_key: String,
  /// hex ed25519 signature (64 bytes).
  pub signature: String,
  /// free-text statement of what this signature does and does not
  /// claim. Kept in the artifact so the claim travels with the proof.
  pub scope: String,
}

pub const SIGN_SCOPE: &str =
  "integrity and provenance within this boot; not non-repudiation against a \
   same-uid adversary with kernel access";

/// An ed25519 signing key held only in process memory.
pub struct SigningKey {
  keypair: Keypair,
}

impl SigningKey {
  /// Generate a fresh key from /dev/urandom. No disk write.
  pub fn generate() -> Result<Self, String> {
    let mut seed = [0u8; 32];
    {
      use std::io::Read;
      let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("open /dev/urandom: {e}"))?;
      f.read_exact(&mut seed).map_err(|e| format!("read entropy: {e}"))?;
    }
    let secret = SecretKey::from_bytes(&seed).map_err(|e| format!("secret key: {e}"))?;
    let public: PublicKey = (&secret).into();
    Ok(Self { keypair: Keypair { secret, public } })
  }

  /// Make this process and its children non-dumpable and disable core
  /// dumps, so the in-memory key cannot be recovered from a core (S0).
  /// Called once at daemon start, before the key is generated.
  pub fn harden_process() {
    // RLIMIT_CORE = 0
    let nolim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: setrlimit is always safe to call with a valid pointer.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &nolim) };
    if rc != 0 {
      eprintln!("castellan-proof: warning: could not set RLIMIT_CORE=0");
    }
    // PR_SET_DUMPABLE = 0
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no memory-safety concerns.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
      eprintln!("castellan-proof: warning: could not clear dumpable");
    }
  }

  pub fn public_hex(&self) -> String {
    self.keypair.public.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
  }

  /// Sign canonical bytes, returning the detached signature artifact.
  pub fn sign(&self, msg: &[u8]) -> CertSignature {
    let sig: Signature = self.keypair.sign(msg);
    CertSignature {
      public_key: self.public_hex(),
      signature: sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect(),
      scope: SIGN_SCOPE.to_string(),
    }
  }
}

/// Verify a signature over `msg`. When `expected_public` is Some, the
/// embedded key must match it (pinning); otherwise the embedded key is
/// trusted and the result reports only that the signature is internally
/// consistent with it.
pub fn verify(
  msg: &[u8],
  sig: &CertSignature,
  expected_public: Option<&str>,
) -> Result<(), String> {
  if let Some(exp) = expected_public {
    if !exp.eq_ignore_ascii_case(&sig.public_key) {
      return Err("public key does not match the pinned key".into());
    }
  }
  let pk_bytes = hex_decode(&sig.public_key).ok_or("malformed public key hex")?;
  let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| "public key must be 32 bytes")?;
  let public = PublicKey::from_bytes(&pk_arr).map_err(|e| format!("public key: {e}"))?;
  let sg_bytes = hex_decode(&sig.signature).ok_or("malformed signature hex")?;
  let sg_arr: [u8; 64] = sg_bytes.try_into().map_err(|_| "signature must be 64 bytes")?;
  let signature = Signature::from_bytes(&sg_arr).map_err(|e| format!("signature: {e}"))?;
  public.verify(msg, &signature).map_err(|_| "signature verification failed".to_string())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
  if s.len() % 2 != 0 {
    return None;
  }
  (0..s.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sign_and_verify_roundtrip() {
    let key = SigningKey::generate().unwrap();
    let sig = key.sign(b"certificate bytes");
    assert!(verify(b"certificate bytes", &sig, None).is_ok());
    assert!(verify(b"certificate bytes", &sig, Some(&key.public_hex())).is_ok());
  }

  #[test]
  fn tampered_message_fails() {
    let key = SigningKey::generate().unwrap();
    let sig = key.sign(b"original");
    assert!(verify(b"tampered", &sig, None).is_err());
  }

  #[test]
  fn wrong_pinned_key_fails() {
    let key = SigningKey::generate().unwrap();
    let other = SigningKey::generate().unwrap();
    let sig = key.sign(b"msg");
    assert!(verify(b"msg", &sig, Some(&other.public_hex())).is_err());
  }

  #[test]
  fn keys_differ_between_generations() {
    let a = SigningKey::generate().unwrap();
    let b = SigningKey::generate().unwrap();
    assert_ne!(a.public_hex(), b.public_hex());
    assert_eq!(a.public_hex().len(), 64);
  }
}
