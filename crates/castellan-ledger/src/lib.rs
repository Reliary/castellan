use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Overlay {
  pub lower: PathBuf,
  pub upper: PathBuf,
  pub work: PathBuf,
  pub merged: PathBuf,
}

/// Set up an overlay view of `project` for this session.
///
/// Called by `castellan launch --undo` right before exec: creates
/// upper/work/merged under `scratch_root`, then forks. The CHILD enters a
/// new user+mount namespace (unprivileged) and mounts overlay with
/// lower=project; the PARENT writes the child's uid_map/gid_map because
/// modern kernels deny self-written maps from inside the namespace (EPERM,
/// verified on kernel 7.0.x). The child then signals the parent's pipe and
/// returns; the caller chdirs into `merged` and execs. All session writes
/// land in `upper`.
pub fn setup(project: &Path, scratch_root: &Path) -> io::Result<Overlay> {
  let project = project.canonicalize()?;
  let dir = scratch_root.join("overlay");
  fs::create_dir_all(&dir)?;
  let upper = dir.join("upper");
  let work = dir.join("work");
  let merged = dir.join("merged");
  fs::create_dir_all(&upper)?;
  fs::create_dir_all(&work)?;
  // stale plain dir from an earlier crashed attempt: its mount died with
  // that session's namespace
  if merged.exists() {
    fs::remove_dir_all(&merged)?;
  }
  fs::create_dir_all(&merged)?;

  // The current process will enter the ns, mount the overlay, and exec the
  // agent. A short-lived helper stays OUTSIDE the namespace and writes our
  // uid_map/gid_map — modern kernels deny self-written maps from inside
  // (EPERM, verified on kernel 7.0.x).
  let me = std::process::id();
  let (ready_rx, ready_tx) = std::os::unix::net::UnixStream::pair()?;
  let (done_rx, done_tx) = std::os::unix::net::UnixStream::pair()?;
  // keep our signaling ends; the helper gets the read side via try_clone
  let mut signal_tx = ready_tx.try_clone()?;
  spawn_map_helper(me, ready_rx, ready_tx, done_tx)?;

  enter_user_mount_ns()?;

  // signal helper: we are inside the ns now
  signal_tx.write_all(b"1")?;
  drop(signal_tx);

  // wait for the helper's confirmation that the maps landed — mounting
  // before uid_map is visible fails with EACCES (race, seen live)
  {
    use std::io::Read;
    let mut done_rx = done_rx;
    let mut ack = [0u8; 1];
    if done_rx.read_exact(&mut ack).is_err() {
      return Err(io::Error::other("map helper died before writing maps"));
    }
  }

  mount_overlay(&project, &upper, &work, &merged)?;
  Ok(Overlay { lower: project, upper, work, merged })
}

/// Fork a helper BEFORE the caller enters its namespace. The helper keeps
/// `ready_rx` (the outside-ns side), waits for the caller's "in-ns" byte,
/// then writes /proc/<target>/setgroups|uid_map|gid_map from outside and
/// exits. The parent keeps `ready_tx` to signal; both sides of the pair
/// are passed because fork duplicates them.
fn spawn_map_helper(
  target_pid: u32,
  ready_rx: std::os::unix::net::UnixStream,
  ready_tx: std::os::unix::net::UnixStream,
  mut done_tx: std::os::unix::net::UnixStream,
) -> io::Result<u32> {
  use nix::unistd::{fork, ForkResult};
  match unsafe { fork() } {
    Ok(ForkResult::Child) => {
      drop(ready_tx);
      let mut rx = ready_rx;
      let mut buf = [0u8; 1];
      if rx.read_exact(&mut buf).is_err() {
        std::process::exit(2);
      }
      let r = (|| -> io::Result<()> {
        fs::write(format!("/proc/{target_pid}/setgroups"), "deny\n")?;
        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();
        fs::write(format!("/proc/{target_pid}/uid_map"), format!("0 {uid} 1\n"))?;
        fs::write(format!("/proc/{target_pid}/gid_map"), format!("0 {gid} 1\n"))?;
        Ok(())
      })();
      if let Err(e) = r {
        eprintln!("castellan-ledger map write failed: {e}");
        std::process::exit(3);
      }
      let _ = done_tx.write_all(b"1");
      std::process::exit(0);
    }
    Ok(ForkResult::Parent { child }) => Ok(u32::try_from(child.as_raw()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?),
    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
  }
}

fn enter_user_mount_ns() -> io::Result<()> {
  use nix::sched::{unshare, CloneFlags};
  unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
    .map_err(|e| io::Error::other(format!("unshare: {e}")))
}

fn mount_overlay(project: &Path, upper: &Path, work: &Path, merged: &Path) -> io::Result<()> {
  use nix::mount::{mount, MsFlags};
  mount::<str, Path, str, str>(
    None,
    Path::new("/"),
    None,
    MsFlags::MS_REC | MsFlags::MS_PRIVATE,
    None,
  )
  .map_err(|e| io::Error::other(format!("remount private: {e}")))?;
  mount::<Path, Path, str, str>(Some(merged), merged, Some("none"), MsFlags::MS_BIND, None)
    .map_err(|e| io::Error::other(format!("bind merged: {e}")))?;
  mount::<str, Path, str, str>(None, merged, None, MsFlags::MS_PRIVATE, None)
    .map_err(|e| io::Error::other(format!("bind private: {e}")))?;
  let opts = format!(
    // NOTE (2026-09-02): redirect_dir=on CANNOT be requested — rootless
    // userns mounts force it off (mount EPERM, verified live on
    // 7.0.3-1-cachyos with CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW
    // unset). Directory rename(2) inside the overlay therefore fails
    // EXDEV; the CLI redirects CARGO_TARGET_DIR into the session
    // scratch when undo is active so toolchains never rename dirs in
    // the merged view.
    "lowerdir={},upperdir={},workdir={}",
    project.display(),
    upper.display(),
    work.display()
  );
  mount::<str, Path, str, str>(
    Some("overlay"),
    merged,
    Some("overlay"),
    MsFlags::empty(),
    Some(opts.as_str()),
  )
  .map_err(|e| io::Error::other(format!("overlay mount: {e}")))?;
  // B6 phase 2 interposition: real harnesses chdir to the canonical
  // project path (`opencode run --dir <canonical>` etc), bypassing
  // the merged view — writes landed on the real fs (D2-F5/D4-F8).
  // Bind merged OVER the canonical path inside the agent's mount ns:
  // the canonical path now resolves to the overlay view, the real
  // project is covered, and `--dir canonical` writes land in upper.
  // Only this process's mount ns sees the bind (MS_PRIVATE above).
  mount::<Path, Path, str, str>(Some(merged), project, Some("none"), MsFlags::MS_BIND, None)
    .map_err(|e| io::Error::other(format!("bind merged over project: {e}")))
}

#[derive(Debug, serde::Serialize)]
pub struct ChangedFile {
  pub path: String,
  pub kind: String,
  pub size: u64,
}

/// Enumerate every entry recorded in the overlay upper layer.
/// Paths are relative to the project root. Overlayfs whiteouts
/// (chardev 0:0) are reported as kind "deleted".
pub fn diff_upper(upper: &Path) -> io::Result<Vec<ChangedFile>> {
  let mut out = Vec::new();
  walk(upper, upper, &mut out)?;
  out.sort_by(|a, b| a.path.cmp(&b.path));
  Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<ChangedFile>) -> io::Result<()> {
  for entry in fs::read_dir(dir)? {
    let path = entry?.path();
    let meta = fs::symlink_metadata(&path)?;
    let ftype = meta.file_type();
    if ftype.is_char_device() && meta.rdev() == 0 {
      out.push(ChangedFile {
        path: rel(root, &path),
        kind: "deleted".into(),
        size: 0,
      });
      continue;
    }
    let kind = if ftype.is_dir() {
      "dir"
    } else if ftype.is_symlink() {
      "symlink"
    } else {
      "file"
    };
    out.push(ChangedFile {
      path: rel(root, &path),
      kind: kind.into(),
      size: meta.len(),
    });
    if ftype.is_dir() {
      walk(root, &path, out)?;
    }
  }
  Ok(())
}

fn rel(root: &Path, p: &Path) -> String {
  p.strip_prefix(root).unwrap_or(p).display().to_string()
}

/// Discard the session's changes: wipe upper + work.
pub fn discard(upper: &Path, work: &Path) -> io::Result<()> {
  for d in [upper, work] {
    if d.exists() {
      fs::remove_dir_all(d)?;
    }
    fs::create_dir_all(d)?;
  }
  Ok(())
}

/// Materialize the session's changes onto the real project.
/// Honors whiteouts as deletions. Returns applied change lines.
pub fn commit(lower: &Path, upper: &Path) -> io::Result<Vec<String>> {
  let mut applied = Vec::new();
  for c in diff_upper(upper)? {
    let src = upper.join(&c.path);
    let dst = lower.join(&c.path);
    match c.kind.as_str() {
      "deleted" => {
        if dst.is_dir() {
          fs::remove_dir_all(&dst)?;
        } else if dst.symlink_metadata().is_ok() {
          fs::remove_file(&dst)?;
        }
        applied.push(format!("- {}", c.path));
      }
      "dir" => {
        fs::create_dir_all(&dst)?;
        applied.push(format!("d {}", c.path));
      }
      _ => {
        if let Some(parent) = dst.parent() {
          fs::create_dir_all(parent)?;
        }
        fs::copy(&src, &dst)?;
        applied.push(format!("+ {}", c.path));
      }
    }
  }
  Ok(applied)
}
