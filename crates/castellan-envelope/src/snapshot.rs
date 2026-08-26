use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Snapshot {
  pub root: PathBuf,
  files: BTreeMap<String, String>,
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>, depth: u8) {
  if depth == 0 {
    return;
  }
  let entries = match fs::read_dir(dir) {
    Ok(e) => e,
    Err(_) => return,
  };
  for entry in entries.flatten() {
    let p = entry.path();
    if p.is_symlink() {
      continue;
    }
    if p.is_dir() {
      walk_files(&p, out, depth - 1);
    } else {
      out.push(p);
    }
  }
}

impl Snapshot {
  pub fn take(root: PathBuf) -> Self {
    let mut files = BTreeMap::new();
    if root.is_dir() {
      let mut paths = Vec::new();
      walk_files(&root, &mut paths, 5);
      for p in paths {
        let rel = p.strip_prefix(&root).unwrap_or(&p).display().to_string();
        let hash = match fs::read(&p) {
          Ok(bytes) => hex(&Sha256::digest(&bytes)),
          Err(_) => "unreadable".to_string(),
        };
        files.insert(rel, hash);
      }
    }
    Self { root, files }
  }

  pub fn diff_since(&self, baseline: &Snapshot) -> Vec<String> {
    let mut drift = Vec::new();
    for (rel, hash) in &self.files {
      match baseline.files.get(rel) {
        None => drift.push(format!("added   {}/{}", baseline.root.display(), rel)),
        Some(h) if h != hash => drift.push(format!("changed {}/{}", baseline.root.display(), rel)),
        Some(_) => {}
      }
    }
    for rel in baseline.files.keys() {
      if !self.files.contains_key(rel) {
        drift.push(format!("removed {}/{}", baseline.root.display(), rel));
      }
    }
    drift
  }
}

fn hex(bytes: &[u8]) -> String {
  bytes.iter().map(|b| format!("{b:02x}")).collect()
}
