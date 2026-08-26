use castellan_core::EventSink;
use castellan_policy::{Op, Policy, Verdict};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, InotifyEvent, WatchDescriptor};
use rustc_hash::FxHashMap;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct AuditWatcher {
  stop: Arc<AtomicBool>,
  handle: Option<std::thread::JoinHandle<()>>,
}

type WatchMap = FxHashMap<WatchDescriptor, PathBuf>;

fn watch_mask() -> AddWatchFlags {
  AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_CREATE
}

fn add_watch_recursive(
  ino: &Inotify,
  map: &mut WatchMap,
  dir: &Path,
  depth: u8,
) {
  if depth == 0 {
    return;
  }
  match ino.add_watch(dir, watch_mask()) {
    Ok(wd) => {
      map.insert(wd, dir.to_path_buf());
    }
    Err(_) => return,
  }
  let entries = match std::fs::read_dir(dir) {
    Ok(e) => e,
    Err(_) => return,
  };
  for entry in entries.flatten() {
    let p = entry.path();
    if p.is_dir() && !p.is_symlink() {
      add_watch_recursive(ino, map, &p, depth - 1);
    }
  }
}

impl AuditWatcher {
  pub fn start(policy: Policy, sink: EventSink) -> Self {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let handle =
      std::thread::Builder::new().name("audit-watch".into()).spawn(move || run_watcher(policy, sink, stop2)).ok();
    Self { stop, handle }
  }

  pub fn stop(&self) {
    self.stop.store(true, Ordering::Relaxed);
  }

  pub fn join(&mut self) {
    if let Some(h) = self.handle.take() {
      let _ = h.join();
    }
  }
}

fn run_watcher(policy: Policy, sink: EventSink, stop: Arc<AtomicBool>) {
  let ino = match Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK) {
    Ok(i) => i,
    Err(_) => return,
  };
  let mut map: WatchMap = FxHashMap::default();
  for root in policy.watch_roots() {
    add_watch_recursive(&ino, &mut map, root, 6);
  }
  if let Ok(home) = std::env::var("HOME") {
    let home = PathBuf::from(home);
    if !policy.watch_roots().any(|r| r == home) {
      if let Ok(wd) = ino.add_watch(&home, watch_mask()) {
        map.insert(wd, home);
      }
    }
  }
  if map.is_empty() {
    return;
  }
  let fd = ino.as_fd().as_raw_fd();

  loop {
    if stop.load(Ordering::Relaxed) {
      return;
    }
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let ready = unsafe { libc::poll(&mut pfd, 1, 500) };
    if ready <= 0 {
      continue;
    }
    let events = match ino.read_events() {
      Ok(e) => e,
      Err(_) => continue,
    };
    for ev in events {
      handle_event(&ino, &policy, &sink, &mut map, ev);
    }
  }
}

fn handle_event(
  ino: &Inotify,
  policy: &Policy,
  sink: &EventSink,
  map: &mut WatchMap,
  ev: InotifyEvent,
) {
  let name = ev.name.unwrap_or_default();
  let dir = match map.get(&ev.wd) {
    Some(d) => d.clone(),
    None => return,
  };
  let path = dir.join(&name);
  if ev.mask.contains(AddWatchFlags::IN_ISDIR)
    && ev.mask.intersects(AddWatchFlags::IN_CREATE | AddWatchFlags::IN_MOVED_TO)
  {
    add_watch_recursive(ino, map, &path, 4);
  }
  if ev.mask.contains(AddWatchFlags::IN_CLOSE_WRITE)
    || ev.mask.intersects(AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_CREATE)
  {
    let verdict = policy.classify(&path, Op::Write);
    let vstr = match verdict {
      Verdict::Allow => "allow",
      Verdict::Deny => "would_deny",
    };
    let _ = sink.emit("fs_write", &path.display().to_string(), vstr);
  }
}
