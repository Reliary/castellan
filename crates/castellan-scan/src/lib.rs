//! P9.2 pluggable artifact scanner at the keep gate.
//!
//! The daemon consumes findings; it does not care who produced them.
//! Any scanner emitting findings JSON adapts to the `Findings` stream.
//!
//! Design commitments (from the P9 plan, antagonised in discussion):
//! - BASELINE-DELTA, never raw scan: scan at spawn (baseline) and at
//!   keep; only NEW findings on session-touched files count. Legacy
//!   findings never punish the project.
//! - FINDINGS-ONLY-NEGATIVE: a clean delta earns NOTHING — no trust,
//!   no cert language, no green mark. There is no wire from "clean"
//!   to any reward, so partial coverage cannot leak absence-of-
//!   evidence into evidence-of-absence.
//! - CONFIG-PINNED: the scanner command comes from the project config
//!   (inside the agent's write roots), so it is pinned at spawn via
//!   config_sha — the same mechanism as test_cmd. A shimmed scanner
//!   is human-visible in the cert (identity + config hash) and can
//!   never EARN trust (findings-only-negative).
//! - NEVER GATES ALONE: one negative input among canary/census/
//!   placebo. No offsetting exists.
//!
//! Kill criterion (ran BEFORE this crate): relay-vuln's own CI-gate
//! mode (`scan --diff-ref`) is direction-discriminating on held-out
//! CVEfixes fix-pairs: 100% (10/10), 100% (30/30), 90% (27/30) —
//! all >= 70%. The scanner's signal is FILE-scoped, not line-scoped;
//! line-scoped harness formulations failed (15%, 20%, 8.3%) and were
//! recorded as harness errors, not scanner failures.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// One scanner finding. The interface is deliberately minimal: any
/// scanner that can emit (file, line, class, severity, rule_id) adapts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
  pub file: String,
  pub line: usize,
  pub class: String,
  pub severity: String,
  pub rule_id: String,
}

/// A scan result: findings + the scanner identity (for the cert).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
  pub scanner: String,
  pub findings: Vec<Finding>,
}

/// The scanner command, read from the project config and pinned at
/// spawn. `cmd` is the full command line (argv); `scanner` is the
/// identity string shown in the cert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
  pub scanner: String,
  pub cmd: Vec<String>,
}

/// Parse relay-vuln JSONL output into findings.
/// relay-vuln emits one JSON object per line with `file`, `line`,
/// `vuln_class`, `vuln_score`, `cwe_label`, `function_name`.
pub fn parse_relay_vuln_jsonl(output: &str) -> Vec<Finding> {
  let mut findings = Vec::new();
  for line in output.lines() {
    if !line.starts_with('{') {
      continue;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
      continue;
    };
    let file = v.get("file").and_then(|x| x.as_str()).unwrap_or("?").to_string();
    let line = v.get("line").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    let class = v
      .get("vuln_class")
      .and_then(|x| x.as_str())
      .or_else(|| v.get("cwe_label").and_then(|x| x.as_str()))
      .unwrap_or("unknown")
      .to_string();
    let score = v.get("vuln_score").and_then(|x| x.as_f64()).unwrap_or(0.0);
    let severity = if score >= 1000.0 {
      "high"
    } else if score >= 100.0 {
      "medium"
    } else {
      "low"
    }
    .to_string();
    let rule_id = v
      .get("function_name")
      .and_then(|x| x.as_str())
      .unwrap_or("?")
      .to_string();
    findings.push(Finding { file, line, class, severity, rule_id });
  }
  findings
}

/// Parse semgrep JSON output (--json) into findings.
/// semgrep emits {"results": [{"path", "start": {"line"}, "check_id",
/// "extra": {"severity", "message"}}]}.
pub fn parse_semgrep_json(output: &str) -> Vec<Finding> {
  let Ok(v) = serde_json::from_str::<serde_json::Value>(output) else {
    return Vec::new();
  };
  let Some(results) = v.get("results").and_then(|x| x.as_array()) else {
    return Vec::new();
  };
  let mut findings = Vec::new();
  for r in results {
    let file = r.get("path").and_then(|x| x.as_str()).unwrap_or("?").to_string();
    let line = r
      .get("start")
      .and_then(|x| x.get("line"))
      .and_then(|x| x.as_u64())
      .unwrap_or(0) as usize;
    let rule_id = r.get("check_id").and_then(|x| x.as_str()).unwrap_or("?").to_string();
    let severity = r
      .get("extra")
      .and_then(|x| x.get("severity"))
      .and_then(|x| x.as_str())
      .unwrap_or("unknown")
      .to_string();
    let class = r
      .get("extra")
      .and_then(|x| x.get("message"))
      .and_then(|x| x.as_str())
      .unwrap_or("?")
      .to_string();
    findings.push(Finding { file, line, class, severity, rule_id });
  }
  findings
}

/// Run a scanner command and parse its output. Returns the findings.
/// The command is config-pinned (see the module doc); the caller
/// verifies the pin BEFORE calling this.
pub fn run_scanner(cfg: &ScannerConfig, project: &Path) -> std::io::Result<ScanResult> {
  let mut cmd = std::process::Command::new(&cfg.cmd[0]);
  cmd.args(&cfg.cmd[1..]).current_dir(project);
  let output = cmd.output()?;
  let stdout = String::from_utf8_lossy(&output.stdout).to_string();
  let findings = if cfg.scanner == "relay-vuln" {
    parse_relay_vuln_jsonl(&stdout)
  } else if cfg.scanner == "semgrep" {
    parse_semgrep_json(&stdout)
  } else {
    Vec::new()
  };
  Ok(ScanResult { scanner: cfg.scanner.clone(), findings })
}

/// Baseline-delta: keep only findings on files the session touched
/// that were NOT in the baseline. `touched` is the set of relative
/// paths the session wrote (from the ledger diff).
pub fn delta_findings(baseline: &ScanResult, current: &ScanResult, touched: &[String]) -> Vec<Finding> {
  let baseline_files: std::collections::HashSet<&str> =
    baseline.findings.iter().map(|f| f.file.as_str()).collect();
  let touched_set: std::collections::HashSet<&str> = touched.iter().map(|s| s.as_str()).collect();
  current
    .findings
    .iter()
    .filter(|f| touched_set.contains(f.file.as_str()) && !baseline_files.contains(f.file.as_str()))
    .cloned()
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn relay_vuln_jsonl_parses() {
    let out = r#"{"file":"probe.c","line":1,"vuln_score":9478.7,"vuln_class":"CWE-476","cwe_label":"CWE-476","function_name":"main"}"#;
    let f = parse_relay_vuln_jsonl(out);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].file, "probe.c");
    assert_eq!(f[0].class, "CWE-476");
    assert_eq!(f[0].severity, "high");
  }

  #[test]
  fn semgrep_json_parses() {
    let out = r#"{"results":[{"path":"a.py","start":{"line":3},"check_id":"python.lang.security.audit.eval","extra":{"severity":"ERROR","message":"eval"}}]}"#;
    let f = parse_semgrep_json(out);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].file, "a.py");
    assert_eq!(f[0].rule_id, "python.lang.security.audit.eval");
  }

  #[test]
  fn delta_keeps_only_new_touched_files() {
    let baseline = ScanResult {
      scanner: "relay-vuln".into(),
      findings: vec![Finding {
        file: "legacy.c".into(),
        line: 1,
        class: "CWE-476".into(),
        severity: "high".into(),
        rule_id: "f".into(),
      }],
    };
    let current = ScanResult {
      scanner: "relay-vuln".into(),
      findings: vec![
        Finding {
          file: "legacy.c".into(),
          line: 1,
          class: "CWE-476".into(),
          severity: "high".into(),
          rule_id: "f".into(),
        },
        Finding {
          file: "new.c".into(),
          line: 5,
          class: "CWE-476".into(),
          severity: "high".into(),
          rule_id: "g".into(),
        },
      ],
    };
    let delta = delta_findings(&baseline, &current, &["new.c".to_string()]);
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].file, "new.c");
  }

  #[test]
  fn delta_ignores_untouched_files() {
    let baseline = ScanResult { scanner: "relay-vuln".into(), findings: vec![] };
    let current = ScanResult {
      scanner: "relay-vuln".into(),
      findings: vec![Finding {
        file: "other.c".into(),
        line: 1,
        class: "CWE-476".into(),
        severity: "high".into(),
        rule_id: "f".into(),
      }],
    };
    let delta = delta_findings(&baseline, &current, &["touched.c".to_string()]);
    assert!(delta.is_empty());
  }
}
