use castellan_core::SessionId;
use rustc_hash::FxHashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
  Write,
  Read,
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
}

fn home() -> PathBuf {
  std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/root"))
}

pub fn harness_state_dirs(harness: &str) -> Vec<PathBuf> {
  let h = home();
  let candidates: &[&str] = match harness {
    "claude" => &[".claude"],
    "codex" => &[".codex"],
    "pi" => &[".pi"],
    "aider" => &[".aider", ".aider.conf.yml"],
    "cursor" => &[".cursor", ".config/Cursor"],
    _ => &[],
  };
  candidates.iter().map(|c| h.join(c)).collect()
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
    let mut write_roots = vec![project.clone()];
    for dir in harness_state_dirs(harness) {
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
}
