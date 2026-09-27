//! Dump the syscall capability-class table for the drift gate.
//!
//! The table itself lives in `syscall_classes.rs` so it is type-checked
//! and sits next to the filter it describes. This binary renders both
//! for `test/syscall-drift.sh`:
//!
//!   filtered <name>       — what blocked_syscalls() ACTUALLY blocks,
//!                           resolved back to names by the crate itself
//!   class <name> <dec>    — one capability class and its members
//!   hardconsts <name> …   — the libc consts a Hard class names
//!   member <cls> <name>   — membership, for attribution
//!   residual <name> <why> — a Probed class's written residual
//!
//! The `filtered` line is the point. The gate compares the class table
//! against the filter's real contents, so editing the table without
//! rebuilding the filter is a visible failure rather than a silent
//! divergence. Comparing a table against a second copy of itself would
//! prove nothing.
//!
//!   cargo run -p castellan-envelope --example syscall-classes

use castellan_envelope::blocked_names;
use castellan_envelope::syscall_classes::{CLASSES, Decision};

fn main() {
  for n in blocked_names() {
    println!("filtered\t{n}");
  }
  for c in CLASSES {
    println!(
      "class\t{}\t{:?}\t{}\t{}\t{}",
      c.name,
      c.decision,
      c.capability,
      c.rationale.replace(['\n', '\t'], " "),
      c.members.join(",")
    );
    println!("hardconsts\t{}\t{}", c.name, c.libc_consts.join(","));
    for m in c.members {
      println!("member\t{}\t{}\t{:?}", c.name, m, c.decision);
    }
  }
  for c in CLASSES {
    if c.decision == Decision::Probed {
      println!("residual\t{}\t{}", c.name, c.rationale.replace('\n', " "));
    }
  }
}
