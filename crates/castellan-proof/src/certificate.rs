//! ProofCertificate assembly (daemon-as-verifier).
//!
//! The agent does NOT generate the certificate. The daemon does, from:
//! - kernel-witnessed event spine (bounds proof)
//! - trust.db events ledger (placebo proof + test re-run evidence)
//!
//! Quality labels (from evidence-pack):
//! - STRONG: bounds pass + placebo pass + test re-run pass
//! - MODERATE: bounds pass + at least one positive (placebo or tests)
//! - WEAK: bounds pass, no positive evidence
//! - NON-EVIDENTIAL: out-of-bounds attempts, or no event spine

use castellan_core::{Event, EventSink};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// S2: canonical bytes a certificate is signed over — deterministic
/// JSON of the certificate with the signature field absent. `to_string`
/// on serde_json::Value is stable for a fixed structure (sorted keys),
/// so both signer and verifier derive identical bytes.
pub fn cert_canonical(cert: &ProofCertificate) -> Vec<u8> {
  let mut v = serde_json::to_value(cert).unwrap_or(serde_json::Value::Null);
  if let Some(obj) = v.as_object_mut() {
    obj.remove("signature");
  }
  serde_json::to_vec(&v).unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundsProof {
  pub writes_inside: usize,
  pub out_of_bounds_attempts: usize,
  pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceboProof {
  pub proofs_passed: usize,
  pub test_rerun_passed: bool,
  pub verdict: String,
}

/// P9.2: artifact-scan factor. Findings-only-negative: a clean delta
/// is None (no claim), a finding delta is Some with the scanner
/// identity and the finding list. The cert states what the scanner
/// CANNOT see, never "0 findings" — absence of evidence is not
/// evidence of absence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactScan {
  pub scanner: String,
  pub new_findings: Vec<String>,
  pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCertificate {
  pub session: String,
  pub project: String,
  pub generated_at: u64,
  pub bounds: BoundsProof,
  pub placebo: PlaceboProof,
  /// N6: orphan census attestation. None = no census file (session
  /// ended before the census existed, or never killed via daemon).
  /// Some((found, killed)) = processes that escaped the session
  /// cgroup via the user manager were found and killed at session end.
  #[serde(default)]
  pub census: Option<(usize, usize)>,
  /// P9.2: artifact-scan factor. None = no scan ran (unconfigured) or
  /// clean delta (findings-only-negative — no claim either way).
  #[serde(default)]
  pub artifact_scan: Option<ArtifactScan>,
  /// S1: spine hash-chain verdict at assembly time. None = no chain
  /// (spine absent or pre-S1 events only). Some = the chain was
  /// verified; `broken_at` names the first edited/deleted line, if any.
  #[serde(default)]
  pub spine_chain: Option<ChainEvidence>,
  /// S2: detached ed25519 signature over `cert_canonical(self)`. None
  /// = the daemon has no signing key (unsigned cert — recorded
  /// honestly, never implied to be signed).
  #[serde(default)]
  pub signature: Option<super::signing::CertSignature>,
  pub quality_label: String,
}

/// S1: the spine chain status embedded in the certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEvidence {
  pub checked: usize,
  pub tip: String,
  pub intact: bool,
  #[serde(default)]
  pub broken_at: Option<String>,
}

impl ProofCertificate {
  pub fn label(&self) -> &str {
    &self.quality_label
  }
}

/// Assemble a certificate for a session from kernel-witnessed state.
/// `state_dir` is the XDG_STATE_HOME root (events live under
/// `castellan/events/<session>.jsonl`).
///
/// `signing_key` (S2): when Some, the certificate is signed with it and
/// the detached signature is embedded. When None, `signature` is None
/// and the certificate is honestly unsigned.
pub fn assemble_certificate(
  session: &str,
  project: &Path,
  state_dir: &Path,
) -> std::io::Result<ProofCertificate> {
  assemble_certificate_inner(session, project, state_dir, None)
}

pub fn assemble_certificate_signed(
  session: &str,
  project: &Path,
  state_dir: &Path,
  signing_key: &super::signing::SigningKey,
) -> std::io::Result<ProofCertificate> {
  assemble_certificate_inner(session, project, state_dir, Some(signing_key))
}

fn assemble_certificate_inner(
  session: &str,
  project: &Path,
  state_dir: &Path,
  signing_key: Option<&super::signing::SigningKey>,
) -> std::io::Result<ProofCertificate> {
  let sink = EventSink::for_session(state_dir, session)?;
  let spine_path = state_dir.join("castellan/events").join(format!("{session}.jsonl"));
  let spine_exists = spine_path.exists();
  let events: Vec<Event> = sink.read_all()?;

  let writes_inside = events
    .iter()
    .filter(|e| e.kind == "fs_write" && e.verdict == "allow")
    .count();
  let out_of_bounds = events
    .iter()
    .filter(|e| e.kind == "fs_write" && e.verdict == "would_deny")
    .count();

  let bounds_verdict = if out_of_bounds == 0 { "STAYED_IN_BOUNDS" } else { "OUT_OF_BOUNDS_ATTEMPT" };

  // placebo + test evidence comes from the trust.db events ledger
  let (proofs_passed, test_rerun_passed) = trust_evidence(project, state_dir, session);

  let placebo_verdict = if proofs_passed > 0 || test_rerun_passed {
    "PLACEBO_CONTROLLED_PASS"
  } else {
    "NO_POSITIVE_EVIDENCE"
  };

  // N6 census attestation: read the census file if present.
  let census = read_census(state_dir, session);

  // P9.2 artifact-scan factor: read the scan evidence from the spine.
  // Findings-only-negative: only a finding delta produces a factor;
  // a clean delta or no scan = None (no claim either way).
  let artifact_scan = read_artifact_scan(state_dir, session);

  // S1: verify the spine hash chain. Include the verdict when at least
  // one event was checked OR a break was found — a break on the very
  // first line has checked==0 and must NOT be reported as "no chain".
  let spine_chain = match sink.verify_chain() {
    Ok(v) if v.checked > 0 || v.broken_at.is_some() => {
      let intact = v.intact();
      Some(ChainEvidence {
        checked: v.checked,
        tip: v.tip,
        intact,
        broken_at: v.broken_at,
      })
    }
    _ => None,
  };

  let quality_label = match (bounds_verdict, proofs_passed, test_rerun_passed, spine_exists) {
    ("STAYED_IN_BOUNDS", p, t, true) if p > 0 && t => "STRONG",
    ("STAYED_IN_BOUNDS", p, _, true) if p > 0 => "MODERATE",
    ("STAYED_IN_BOUNDS", _, t, true) if t => "MODERATE",
    ("STAYED_IN_BOUNDS", _, _, true) => "WEAK",
    _ => "NON-EVIDENTIAL",
  };

  let mut cert = ProofCertificate {
    session: session.to_string(),
    project: project.display().to_string(),
    generated_at: castellan_core::now_unix(),
    bounds: BoundsProof {
      writes_inside,
      out_of_bounds_attempts: out_of_bounds,
      verdict: bounds_verdict.to_string(),
    },
    placebo: PlaceboProof {
      proofs_passed,
      test_rerun_passed,
      verdict: placebo_verdict.to_string(),
    },
    census,
    artifact_scan,
    spine_chain,
    signature: None,
    quality_label: quality_label.to_string(),
  };
  if let Some(key) = signing_key {
    cert.signature = Some(key.sign(&cert_canonical(&cert)));
  }
  Ok(cert)
}

/// Read the P9.2 artifact-scan factor from the session spine. The
/// daemon emits `vuln_introduced` events with the finding summary;
/// the scanner identity and scope are recorded in the event detail.
fn read_artifact_scan(state_dir: &Path, session: &str) -> Option<ArtifactScan> {
  let sink = EventSink::for_session(state_dir, session).ok()?;
  let events = sink.read_all().ok()?;
  let ev = events.iter().find(|e| e.kind == "vuln_introduced")?;
  let detail = ev.path.clone();
  let scanner = detail
    .split("scanner=")
    .nth(1)
    .and_then(|s| s.split(')').next())
    .unwrap_or("unknown")
    .to_string();
  let new_findings: Vec<String> = detail
    .split(": ")
    .nth(1)
    .map(|s| s.split(';').map(|f| f.trim().to_string()).collect())
    .unwrap_or_default();
  Some(ArtifactScan {
    scanner,
    new_findings,
    scope: "session-touched files only; scanner coverage is partial — absence of findings is NOT evidence of safety".into(),
  })
}

/// Read the N6 census attestation file written by the daemon at kill.
fn read_census(state_dir: &Path, session: &str) -> Option<(usize, usize)> {
  let path = state_dir.join("castellan/sessions").join(format!("{session}.census"));
  let raw = std::fs::read_to_string(path).ok()?;
  let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
  let found = v.get("orphans_found")?.as_u64()? as usize;
  let killed = v.get("orphans_killed")?.as_u64()? as usize;
  Some((found, killed))
}

/// Pull placebo/test evidence from the trust.db events ledger for the
/// project, scoped to THIS session (a certificate proves one session).
/// Returns (proofs_passed_count, test_rerun_passed).
fn trust_evidence(project: &Path, state_dir: &Path, session: &str) -> (usize, bool) {
  let db_path = state_dir.join("castellan/trust.db");
  let Ok(conn) = rusqlite::Connection::open(&db_path) else {
    return (0, false);
  };
  let hash = project_hash(project);
  let Ok(mut stmt) = conn.prepare(
    "SELECT signal, evidence_json FROM events WHERE realpath_hash = ?1 AND session_uuid = ?2",
  ) else {
    return (0, false);
  };
  let Ok(rows) = stmt.query_map(rusqlite::params![hash, session], |r| {
    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
  }) else {
    return (0, false);
  };
  let mut proofs = 0usize;
  let mut tests = false;
  for row in rows.flatten() {
    match row.0.as_str() {
      "proof_passed" if row.1.contains("placebo-controlled") => proofs += 1,
      "proof_passed" if row.1.contains("test suite") => tests = true,
      _ => {}
    }
  }
  (proofs, tests)
}

fn project_hash(realpath: &Path) -> String {
  use sha2::{Digest, Sha256};
  let canon = realpath.canonicalize().unwrap_or_else(|_| realpath.to_path_buf());
  let digest = Sha256::digest(canon.to_string_lossy().as_bytes());
  digest.iter().map(|b| format!("{b:02x}")).collect()
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
    let dir = std::env::temp_dir().join(format!("castellan-cert-test-{ts}"));
    fs::create_dir_all(&dir).unwrap();
    dir
  }

  #[test]
  fn clean_session_is_weak_without_positive_evidence() {
    let state = tmp_state();
    let sink = EventSink::for_session(&state, "s1").unwrap();
    sink.emit("fs_write", "/proj/a.c", "allow").unwrap();
    let cert = assemble_certificate("s1", Path::new("/tmp/proj"), &state).unwrap();
    assert_eq!(cert.bounds.verdict, "STAYED_IN_BOUNDS");
    assert_eq!(cert.quality_label, "WEAK");
  }

  #[test]
  fn out_of_bounds_is_non_evidential() {
    let state = tmp_state();
    let sink = EventSink::for_session(&state, "s2").unwrap();
    sink.emit("fs_write", "/proj/a.c", "allow").unwrap();
    sink.emit("fs_write", "/etc/passwd", "would_deny").unwrap();
    let cert = assemble_certificate("s2", Path::new("/tmp/proj"), &state).unwrap();
    assert_eq!(cert.bounds.verdict, "OUT_OF_BOUNDS_ATTEMPT");
    assert_eq!(cert.quality_label, "NON-EVIDENTIAL");
  }

  #[test]
  fn no_event_spine_is_non_evidential() {
    let state = tmp_state();
    let cert = assemble_certificate("s3", Path::new("/tmp/proj"), &state).unwrap();
    assert_eq!(cert.quality_label, "NON-EVIDENTIAL");
  }

  #[test]
  fn census_attestation_is_read_from_file() {
    let state = tmp_state();
    let sessions = state.join("castellan/sessions");
    fs::create_dir_all(&sessions).unwrap();
    fs::write(
      sessions.join("s4.census"),
      r#"{"session":"s4","orphans_found":2,"orphans_killed":1,"ts":123}"#,
    )
    .unwrap();
    let cert = assemble_certificate("s4", Path::new("/tmp/proj"), &state).unwrap();
    assert_eq!(cert.census, Some((2, 1)));
  }

  #[test]
  fn missing_census_file_is_none() {
    let state = tmp_state();
    let cert = assemble_certificate("s5", Path::new("/tmp/proj"), &state).unwrap();
    assert_eq!(cert.census, None);
  }
}
