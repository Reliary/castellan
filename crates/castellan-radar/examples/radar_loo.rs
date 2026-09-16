// Honest radar false-positive measurement: leave-one-out.
//
// The daemon folds kept sessions into the project prototype, so querying
// a kept session against the live prototype compares it with itself —
// cosine ~1.0 guaranteed, zero FP by construction. This probe removes
// that bias: encode every session's spine, then for each session
// compare it against the bundle of ALL OTHER sessions only.
//
// Usage: radar_loo <state_dir> <session_id> [session_id...]
// Prints per-session cosine (vs the others) and the FP count at the
// production threshold.

use castellan_radar::{encode_session_from_spine, Hypervector, Prototype};
use std::path::Path;

fn main() {
  let args: Vec<String> = std::env::args().collect();
  if args.len() < 3 {
    eprintln!("usage: radar_loo <state_dir> <session> [session...]");
    std::process::exit(2);
  }
  let state = Path::new(&args[1]);
  let sessions: Vec<String> = args[2..].to_vec();

  // encode all sessions present; skip ones with unreadable spines
  let mut encoded: Vec<(String, Hypervector)> = Vec::new();
  for s in &sessions {
    match encode_session_from_spine(s, state) {
      Ok(hv) => encoded.push((s.clone(), hv)),
      Err(e) => eprintln!("skip {s}: {e}"),
    }
  }
  if encoded.len() < 2 {
    eprintln!("need at least 2 encodable sessions");
    std::process::exit(3);
  }

  let threshold = std::env::var("RADAR_THRESHOLD")
    .ok()
    .and_then(|v| v.parse::<f64>().ok())
    .unwrap_or(0.6);

  let mut fp = 0usize;
  println!("leave-one-out (each session vs the PROTOTYPE of the others, real math):");
  for (i, (sid, hv)) in encoded.iter().enumerate() {
    // Build the prototype exactly as the daemon does (Prototype::fold
    // per kept session), excluding this session — that is the honest
    // "would the live system flag this on first sight" question.
    let mut proto = Prototype::empty();
    let mut n = 0;
    for (j, (_, oh)) in encoded.iter().enumerate() {
      if i == j {
        continue;
      }
      proto.fold(oh);
      n += 1;
    }
    let cos = proto.compare(hv);
    let anomaly = cos < threshold;
    if anomaly {
      fp += 1;
    }
    println!("  {sid} cos={cos:.3} others={n} {}", if anomaly { "ANOMALY" } else { "normal" });
  }
  println!(
    "\nthreshold={threshold:.2}  anomalies={fp}/{} ({:.0}%)",
    encoded.len(),
    100.0 * fp as f64 / encoded.len() as f64
  );
}
