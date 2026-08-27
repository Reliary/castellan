use castellan_core::SessionId;
use rustc_hash::FxHashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
  Write,
  Read,
}

/// Network policy for an enforced session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetMode {
  /// Kernel-deny all TCP connect except the listed ports (the canary
  /// honeypot). Residual: the same port number on OTHER hosts is also
  /// reachable — Landlock net rules are port-scoped, not address-scoped.
  Loopback(Vec<u16>),
  /// No net restriction in v0 (Landlock handles nothing net-related).
  Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
  Allow,
  Deny,
}

#[derive(Debug, Clone)]
pub struct Policy {
  pub session: SessionId,
  pub project: PathBuf,
  write_roots: Vec<PathBuf>,
  deny_write: Vec<PathBuf>,
  allow_write: Vec<PathBuf>,
  net: NetMode,
}

impl Policy {
  pub fn net(&self) -> &NetMode {
    &self.net
  }

  pub fn set_net(&mut self, net: NetMode) {
    self.net = net;
  }
}

fn home() -> PathBuf {
  std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/root"))
}

pub fn harness_state_dirs(harness: &str) -> Vec<PathBuf> {
  harness_state_dirs_with_config(harness, None)
}

const KNOWN_HARNESSES: &[(&str, &[&str])] = &[
  ("claude", &[".claude"]),
  ("codex", &[".codex"]),
  ("pi", &[".pi"]),
  ("opencode", &[".config/opencode", ".local/share/opencode"]),
  ("aider", &[".aider"]),
  ("cursor-agent", &[".cursor", ".config/Cursor"]),
  ("gemini", &[".gemini"]),
  ("crush", &[".config/crush"]),
];

pub fn detect_harness(argv0: &str) -> Option<&'static str> {
  let base = Path::new(argv0).file_name()?.to_str()?;
  KNOWN_HARNESSES.iter().find(|(n, _)| *n == base).map(|(n, _)| *n)
}

fn custom_harness_config() -> Option<toml::Value> {
  let path = std::env::var("XDG_CONFIG_HOME")
    .map(PathBuf::from)
    .unwrap_or_else(|_| home().join(".config"))
    .join("castellan/harnesses.toml");
  let content = std::fs::read_to_string(&path).ok()?;
  toml::from_str(&content).ok()
}

fn harness_state_dirs_with_config(harness: &str, config: Option<&toml::Value>) -> Vec<PathBuf> {
  let h = home();
  let mut dirs = match KNOWN_HARNESSES.iter().find(|(n, _)| *n == harness) {
    Some((_, candidates)) => candidates.iter().map(|c| h.join(c)).collect::<Vec<_>>(),
    None => Vec::new(),
  };
  if let Some(cfg) = config {
    if let Some(entry) = cfg.get(harness) {
      if let Some(list) = entry.get("state_dirs").and_then(|v| v.as_array()) {
        for v in list {
          if let Some(s) = v.as_str() {
            let p = match s.strip_prefix("~/") {
              Some(rest) => h.join(rest),
              None => PathBuf::from(s),
            };
            dirs.push(p);
          }
        }
      }
    }
  }
  dirs
}

pub fn always_deny_write() -> Vec<PathBuf> {
  let h = home();
  vec![
    h.join(".ssh"),
    h.join(".gnupg"),
    h.join(".config/systemd"),
    h.join(".config/autostart"),
    h.join(".local/share/applications"),
    h.join(".bashrc"),
    h.join(".zshrc"),
    h.join(".profile"),
    h.join(".bash_profile"),
    h.join(".zprofile"),
    h.join(".zshenv"),
    h.join(".config/environment.d"),
    h.join(".pam_environment"),
    PathBuf::from("/boot"),
    PathBuf::from("/etc"),
    PathBuf::from("/usr"),
    PathBuf::from("/sys"),
    PathBuf::from("/proc"),
  ]
}

pub fn always_allow_write() -> Vec<PathBuf> {
  ["/dev/null", "/dev/full", "/dev/tty"].map(PathBuf::from).to_vec()
}

impl Policy {
  pub fn new(session: &str, harness: &str, project: PathBuf) -> Self {
    let config = custom_harness_config();
    let mut write_roots = vec![project.clone()];
    for dir in harness_state_dirs_with_config(harness, config.as_ref()) {
      if dir.is_dir() {
        write_roots.push(dir);
      }
    }
    let scratch = std::env::var("XDG_STATE_HOME")
      .map(PathBuf::from)
      .unwrap_or_else(|_| home().join(".local/state"));
    write_roots.push(scratch.join("castellan/sessions").join(session));
    Self {
      session: session.to_owned(),
      project,
      write_roots,
      deny_write: always_deny_write(),
      allow_write: always_allow_write(),
      net: NetMode::Open,
    }
  }

  fn contains_path(root: &Path, path: &Path) -> bool {
    path.starts_with(root)
  }

  pub fn classify(&self, path: &Path, op: Op) -> Verdict {
    let canonical = normalize(path);
    match op {
      Op::Read => Verdict::Allow,
      Op::Write => {
        if self.allow_write.iter().any(|r| Self::contains_path(r, &canonical)) {
          return Verdict::Allow;
        }
        for denied in &self.deny_write {
          if Self::contains_path(denied, &canonical) {
            return Verdict::Deny;
          }
        }
        if Self::contains_path(&self.project, &canonical)
          || self.write_roots.iter().any(|r| Self::contains_path(r, &canonical))
        {
          return Verdict::Allow;
        }
        Verdict::Deny
      }
    }
  }

  pub fn write_roots(&self) -> &[PathBuf] {
    &self.write_roots
  }

  pub fn allow_write_roots(&self) -> &[PathBuf] {
    &self.allow_write
  }

  pub fn watch_roots(&self) -> impl Iterator<Item = &Path> + '_ {
    let mut seen: FxHashSet<PathBuf> = FxHashSet::default();
    self
      .write_roots
      .iter()
      .filter(|p| p.is_dir())
      .filter(move |p| seen.insert((*p).clone()))
      .map(|p| p.as_path())
  }
}

fn normalize(path: &Path) -> PathBuf {
  let mut out = PathBuf::new();
  for comp in path.components() {
    match comp {
      std::path::Component::CurDir => {}
      c => out.push(c),
    }
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  fn policy(project: &str) -> Policy {
    Policy::new("stest", "claude", PathBuf::from(project))
  }

  #[test]
  fn workspace_writes_allowed() {
    let p = policy("/tmp/proj");
    assert_eq!(p.classify(Path::new("/tmp/proj/src/main.rs"), Op::Write), Verdict::Allow);
    assert_eq!(p.classify(Path::new("/tmp/projectile"), Op::Write), Verdict::Deny);
  }

  #[test]
  fn ssh_denied_even_if_inside_other_root() {
    let h = home();
    let p = Policy::new("stest", "claude", h.clone());
    assert_eq!(p.classify(&h.join(".ssh/id_ed25519"), Op::Write), Verdict::Deny);
    assert_eq!(p.classify(&h.join(".gnupg/x"), Op::Write), Verdict::Deny);
    assert_eq!(p.classify(&h.join("work/notes.txt"), Op::Write), Verdict::Allow);
  }

  #[test]
  fn shell_rcs_denied() {
    let p = policy("/tmp/proj");
    assert_eq!(p.classify(Path::new("/home/x/.bashrc"), Op::Write), Verdict::Deny);
    assert_eq!(p.classify(Path::new("/home/x/.zshenv"), Op::Write), Verdict::Deny);
  }

  #[test]
  fn outside_everything_denied() {
    let p = policy("/tmp/proj");
    assert_eq!(p.classify(Path::new("/etc/passwd"), Op::Write), Verdict::Deny);
    assert_eq!(p.classify(Path::new("/opt/thing"), Op::Write), Verdict::Deny);
  }

  #[test]
  fn reads_allowed_broadly() {
    let p = policy("/tmp/proj");
    assert_eq!(p.classify(Path::new("/etc/passwd"), Op::Read), Verdict::Allow);
    assert_eq!(p.classify(Path::new("/home/x/.ssh/id_ed25519"), Op::Read), Verdict::Allow);
  }

  #[test]
  fn prefix_boundary_is_componentwise() {
    let p = policy("/tmp/proj");
    assert_eq!(p.classify(Path::new("/tmp/projx/file"), Op::Write), Verdict::Deny);
  }

  #[test]
  fn normalization_collapses_dot_components() {
    let p = policy("/tmp/proj");
    assert_eq!(
      p.classify(Path::new("/tmp/./proj/../proj/src/lib.rs"), Op::Write),
      Verdict::Allow
    );
  }

  #[test]
  fn systemd_user_units_denied() {
    let p = policy("/tmp/proj");
    assert_eq!(
      p.classify(Path::new("/home/x/.config/systemd/user/evil.service"), Op::Write),
      Verdict::Deny
    );
    assert_eq!(
      p.classify(Path::new("/home/x/.config/autostart/evil.desktop"), Op::Write),
      Verdict::Deny
    );
  }

  #[test]
  fn detect_harness_matches_basename() {
    assert_eq!(detect_harness("/usr/bin/claude"), Some("claude"));
    assert_eq!(detect_harness("codex"), Some("codex"));
    assert_eq!(detect_harness("/usr/local/bin/opencode"), Some("opencode"));
    assert_eq!(detect_harness("/usr/bin/python3"), None);
  }

  #[test]
  fn custom_harness_toml_merges_state_dirs() {
    let cfg: toml::Value = toml::from_str(
      r#"
[myagent]
state_dirs = ["~/myagent-state", "/var/lib/myagent"]
"#,
    )
    .unwrap();
    let dirs = harness_state_dirs_with_config("myagent", Some(&cfg));
    assert_eq!(dirs.len(), 2);
    assert!(dirs[0].ends_with("myagent-state"));
    assert_eq!(dirs[1], Path::new("/var/lib/myagent"));
    assert!(harness_state_dirs_with_config("claude", Some(&cfg)).iter().all(|d| d.ends_with(".claude")));
  }
}
