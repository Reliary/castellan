#![no_main]

use libfuzzer_sys::fuzz_target;

// Canary ledger load path: a corrupted or partial line must never
// panic the daemon at restart (restart-survival is load-bearing for
// S0 — canaries must survive without re-registration).
fuzz_target!(|data: &[u8]| {
  castellan_canary::fuzz_api::load_ledger_bytes(data);
});
