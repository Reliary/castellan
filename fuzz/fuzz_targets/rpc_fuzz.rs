#![no_main]

use libfuzzer_sys::fuzz_target;

// The daemon's control plane: agent-origin bytes decoded as Request
// over the unix socket. Malformed frames must error, never panic.
fuzz_target!(|data: &[u8]| {
  let _ = serde_json::from_slice::<castellan_core::Request>(data);
});
