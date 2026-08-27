//! Placebo-controlled proof pipeline (port of proof-fixes, pure Rust).
//!
//! For any finding, mine the fix pattern (sink -> guard), generate
//! candidate fixes, and emit ONLY fixes that pass a placebo-controlled
//! proof:
//!   - inserting the guard drops the danger signal
//!   - inserting a neutral placeholder (placebo) does NOT drop it
//!
//! Grammar-free: byte-scan counters, no AST, no parsers.

pub mod certificate;

use castellan_ledger::diff_upper;
use std::path::Path;

// ---------------- danger signal (grammar-free byte-scan) ----------------

/// Count unguarded dangerous sites (derefs without prior null check,
/// frees/closes without prior open). Deterministic byte-scan.
pub fn danger_signal(body: &[u8]) -> usize {
  let mut score = 0usize;
  if body.contains(&b'*') {
    // derefs: count derefs not preceded (within 3 tokens) by NULL check.
    // Skip declarations: `*` immediately preceded by a type keyword.
    for m in deref_matches(body) {
      let before = &body[m.saturating_sub(8)..m];
      if is_declaration(before) {
        continue;
      }
      let pre = &body[m.saturating_sub(160)..m];
      if !has_null_check(pre) {
        score += 1;
      }
    }
  }
  if contains_any(body, b"fclose", b"close") {
    for m in close_matches(body) {
      let pre = &body[m.saturating_sub(200)..m];
      if !has_open(pre) {
        score += 1;
      }
    }
  }
  if contains_any(body, b"free", b"free") {
    for m in free_matches(body) {
      let pre = &body[m.saturating_sub(200)..m];
      if !has_open(pre) {
        score += 1;
      }
    }
  }
  score
}

fn deref_matches(body: &[u8]) -> Vec<usize> {
  // `*` followed by an identifier start
  let mut out = Vec::new();
  let mut i = 0;
  while i + 1 < body.len() {
    if body[i] == b'*' && body[i + 1].is_ascii_alphabetic() {
      out.push(i);
    }
    i += 1;
  }
  out
}

fn close_matches(body: &[u8]) -> Vec<usize> {
  let mut out = Vec::new();
  for pat in [b"fclose(" as &[u8], b"close(" as &[u8]] {
    let mut i = 0;
    while i + pat.len() <= body.len() {
      if body[i..i + pat.len()] == *pat {
        out.push(i);
      }
      i += 1;
    }
  }
  out
}

fn free_matches(body: &[u8]) -> Vec<usize> {
  let mut out = Vec::new();
  let pat = b"free(";
  let mut i = 0;
  while i + pat.len() <= body.len() {
    if body[i..i + pat.len()] == *pat {
      out.push(i);
    }
    i += 1;
  }
  out
}

fn contains_any(body: &[u8], a: &[u8], b: &[u8]) -> bool {
  body.windows(a.len()).any(|w| w == a) || body.windows(b.len()).any(|w| w == b)
}

fn is_declaration(before: &[u8]) -> bool {
  // `*` immediately preceded by a type keyword
  let s = String::from_utf8_lossy(before);
  let s = s.trim_end();
  let last_word = s.rsplit(|c: char| c.is_whitespace()).next().unwrap_or("");
  matches!(
    last_word,
    "char" | "int" | "void" | "float" | "double" | "struct" | "unsigned" | "long"
  )
}

fn has_null_check(pre: &[u8]) -> bool {
  // `if (... NULL ...)` within the preceding window
  let s = String::from_utf8_lossy(pre);
  let s = s.to_lowercase();
  s.contains("if") && s.contains("null")
}

fn has_open(pre: &[u8]) -> bool {
  let s = String::from_utf8_lossy(pre);
  s.contains("fopen") || s.contains("open(")
}

// ---------------- fix-pattern mining ----------------

#[derive(Debug, Clone)]
pub struct FixPattern {
  pub cwe: &'static str,
  pub trigger: &'static str, // regex fragment identifying the sink
  pub guard_prefix: &'static str, // e.g. "if ({{NAME}} == NULL) return;"
}

pub const FIX_TEMPLATES: [FixPattern; 3] = [
  FixPattern {
    cwe: "CWE-476",
    trigger: r"\*\s*(\w+)",
    guard_prefix: "if ({{NAME}} == NULL) return;",
  },
  FixPattern {
    cwe: "CWE-401",
    trigger: r"\bfclose\s*\((\w+)\)",
    guard_prefix: "if ({{NAME}} != NULL) fclose({{NAME}});",
  },
  FixPattern {
    cwe: "CWE-416",
    trigger: r"\bfree\s*\((\w+)\)",
    guard_prefix: "if ({{NAME}} != NULL) free({{NAME}});",
  },
];

// ---------------- placebo-controlled proof ----------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProofResult {
  pub finding_id: String,
  pub cwe: String,
  pub before: usize,
  pub after_guard: usize,
  pub after_placebo: usize,
  pub guard_text: String,
  pub passed: bool,
}

impl ProofResult {
  pub fn strength(&self) -> f64 {
    if self.before == 0 {
      return 0.0;
    }
    (self.before - self.after_guard) as f64 / self.before as f64
  }
}

fn insert_guard(body: &[u8], guard: &str, sink_name: &str) -> Vec<u8> {
  let guard_line = guard.replace("{{NAME}}", sink_name);
  // insert inline right before the deref/free site, skipping declarations
  let deref_pat = format!("*{sink_name}");
  let free_pat = format!("free({sink_name}");
  let close_pat = format!("fclose({sink_name}");
  for pat in [deref_pat.as_bytes(), free_pat.as_bytes(), close_pat.as_bytes()] {
    let mut i = 0;
    while i + pat.len() <= body.len() {
      if &body[i..i + pat.len()] == pat {
        let before = &body[i.saturating_sub(8)..i];
        if is_declaration(before) {
          i += 1;
          continue;
        }
        let mut out = Vec::with_capacity(body.len() + guard_line.len() + 1);
        out.extend_from_slice(&body[..i]);
        out.extend_from_slice(guard_line.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&body[i..]);
        return out;
      }
      i += 1;
    }
  }
  let mut out = Vec::with_capacity(body.len() + guard_line.len() + 1);
  out.extend_from_slice(guard_line.as_bytes());
  out.push(b'\n');
  out.extend_from_slice(body);
  out
}

/// Placebo-controlled proof: real guard vs neutral placeholder.
pub fn prove_fix(body: &[u8], guard_template: &str, cwe: &str) -> ProofResult {
  let sink = extract_sink(body, cwe).unwrap_or_else(|| "ptr".to_string());
  let before = danger_signal(body);
  let guard = guard_template.replace("{{NAME}}", &sink);
  let after_guard = danger_signal(&insert_guard(body, &guard, &sink));
  let placebo = format!("/* neutral */ {sink} = {sink}; /* no-op */");
  let after_placebo = danger_signal(&insert_guard(body, &placebo, &sink));
  let passed = after_guard < before && after_placebo >= after_guard;
  ProofResult {
    finding_id: format!("fix:{sink}:{}", body.len()),
    cwe: cwe.to_string(),
    before,
    after_guard,
    after_placebo,
    guard_text: guard,
    passed,
  }
}

fn extract_sink(body: &[u8], cwe: &str) -> Option<String> {
  let s = String::from_utf8_lossy(body);
  let s = s.as_ref();
  match cwe {
    "CWE-476" => {
      // first `*identifier` occurrence
      let bytes = s.as_bytes();
      let mut i = 0;
      while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1].is_ascii_alphabetic() {
          let start = i + 1;
          let mut end = start;
          while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
          }
          return Some(s[start..end].to_string());
        }
        i += 1;
      }
      None
    }
    "CWE-401" => {
      let pat = "fclose(";
      if let Some(idx) = s.find(pat) {
        let start = idx + pat.len();
        let rest = &s[start..];
        let end = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
      }
      None
    }
    "CWE-416" => {
      let pat = "free(";
      if let Some(idx) = s.find(pat) {
        let start = idx + pat.len();
        let rest = &s[start..];
        let end = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
      }
      None
    }
    _ => None,
  }
}

// ---------------- session-level placebo ----------------

/// Pair-based placebo proof: the session's ACTUAL edit (orig -> new) must
/// drop the danger signal more than a neutral placeholder would.
///
/// - `before` = danger of the original body (pre-session, from the project)
/// - `after_guard` = danger of the new body (post-session, from the upper)
/// - `after_placebo` = danger of the original with a no-op inserted
///
/// passed = the real edit drops danger AND the placebo does not.
/// This is the honest formulation: it proves the session's real change is
/// danger-reducing, not merely that a template guard would be.
pub fn prove_fix_pair(orig: &[u8], new: &[u8], cwe: &str) -> ProofResult {
  let sink = extract_sink(orig, cwe).unwrap_or_else(|| "ptr".to_string());
  let before = danger_signal(orig);
  let after_guard = danger_signal(new);
  let placebo = format!("/* neutral */ {sink} = {sink}; /* no-op */");
  let after_placebo = danger_signal(&insert_guard(orig, &placebo, &sink));
  let passed = after_guard < before && after_placebo >= after_guard;
  ProofResult {
    finding_id: format!("fix:{sink}:{}", orig.len()),
    cwe: cwe.to_string(),
    before,
    after_guard,
    after_placebo,
    guard_text: String::new(),
    passed,
  }
}

/// Run the pair-based placebo proof over every changed file in the
/// session's upper layer, comparing against the original in the project.
/// Returns proofs that passed (danger-reducing, placebo-controlled).
/// New files (no original) and deletions are skipped: no proof possible.
pub fn run_session_placebo(project: &Path, upper: &Path) -> Vec<ProofResult> {
  let mut passed = Vec::new();
  let Ok(changed) = diff_upper(upper) else { return passed };
  for c in changed {
    if c.kind != "file" {
      continue;
    }
    // original body from the real project (lower layer)
    let Ok(orig) = std::fs::read(project.join(&c.path)) else { continue };
    // new body from the session's upper layer
    let Ok(new) = std::fs::read(upper.join(&c.path)) else { continue };
    // one proof per file: the first passing template is enough
    for tpl in FIX_TEMPLATES.iter() {
      let proof = prove_fix_pair(&orig, &new, tpl.cwe);
      if proof.passed {
        passed.push(proof);
        break;
      }
    }
  }
  passed
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn danger_signal_counts_derefs() {
    let body = b"int parse(char* p) { char* q = malloc(16); *q = 1; return 0; }";
    assert!(danger_signal(body) >= 1);
  }

  #[test]
  fn danger_signal_zero_for_guarded() {
    let body = b"int parse(char* p) { char* q = malloc(16); if (q == NULL) return -1; *q = 1; return 0; }";
    assert_eq!(danger_signal(body), 0);
  }

  #[test]
  fn danger_signal_counts_fclose_without_open() {
    let body = b"void rd(FILE* f) { fclose(f); }";
    assert!(danger_signal(body) >= 1);
  }

  #[test]
  fn danger_signal_zero_for_open_close() {
    // no derefs; close preceded by open in the pre-window
    let body = b"void rd() { int fd = open(\"x\", 0); close(fd); }";
    assert_eq!(danger_signal(body), 0);
  }

  #[test]
  fn danger_signal_counts_close_without_open() {
    // null-check guard does NOT help fclose — only an open in the
    // pre-window does (Python-faithful semantics)
    let body = b"void rd() { int fd = 3; close(fd); }";
    assert_eq!(danger_signal(body), 1);
  }

  #[test]
  fn prove_fix_passes_for_real_guard() {
    let body = b"int parse(char* p) { char* q = malloc(16); *q = 1; return 0; }";
    let proof = prove_fix(body, "if ({{NAME}} == NULL) return;", "CWE-476");
    assert!(proof.passed);
    assert!(proof.after_guard < proof.before);
    assert!(proof.after_placebo >= proof.after_guard);
  }

  #[test]
  fn prove_fix_fails_for_placebo_only() {
    // a "fix" that is itself a placebo: no-op assignment
    let body = b"int parse(char* p) { char* q = malloc(16); *q = 1; return 0; }";
    let proof = prove_fix(body, "/* neutral */ {{NAME}} = {{NAME}};", "CWE-476");
    assert!(!proof.passed);
  }

  #[test]
  fn prove_fix_fails_for_assert_true() {
    // `assert True` is a placebo: doesn't drop danger
    let body = b"int parse(char* p) { char* q = malloc(16); *q = 1; return 0; }";
    let proof = prove_fix(body, "assert True;", "CWE-476");
    assert!(!proof.passed);
  }

  #[test]
  fn strength_is_zero_when_no_danger() {
    let body = b"int parse(char* p) { return 0; }";
    let proof = prove_fix(body, "if ({{NAME}} == NULL) return;", "CWE-476");
    assert_eq!(proof.strength(), 0.0);
  }

  #[test]
  fn extract_sink_finds_identifier() {
    let body = b"int parse(char* p) { char* q = malloc(16); *q = 1; }";
    assert_eq!(extract_sink(body, "CWE-476"), Some("q".to_string()));
  }

  #[test]
  fn prove_fix_pair_passes_for_real_edit() {
    let orig = b"int parse(char* p) { char* q = malloc(16); *q = 1; return 0; }";
    let new = b"int parse(char* p) { char* q = malloc(16); if (q == NULL) return -1; *q = 1; return 0; }";
    let proof = prove_fix_pair(orig, new, "CWE-476");
    assert!(proof.passed);
    assert_eq!(proof.before, 1);
    assert_eq!(proof.after_guard, 0);
  }

  #[test]
  fn prove_fix_pair_fails_for_assert_true_edit() {
    // agent "fixed" by adding `assert True` — placebo, no danger drop
    let orig = b"int parse(char* p) { char* q = malloc(16); *q = 1; return 0; }";
    let new = b"int parse(char* p) { char* q = malloc(16); assert True; *q = 1; return 0; }";
    let proof = prove_fix_pair(orig, new, "CWE-476");
    assert!(!proof.passed);
  }

  #[test]
  fn prove_fix_pair_passes_for_deletion_edit() {
    // deleting the dangerous line genuinely drops danger (the no-op
    // placebo does not) — a real danger reduction, so the pair proof
    // passes. The template proof can't express deletion; the pair proof
    // can, and it is honest: the danger IS gone.
    let orig = b"int parse(char* p) { char* q = malloc(16); *q = 1; return 0; }";
    let new = b"int parse(char* p) { return 0; }";
    let proof = prove_fix_pair(orig, new, "CWE-476");
    assert!(proof.passed);
  }
}
