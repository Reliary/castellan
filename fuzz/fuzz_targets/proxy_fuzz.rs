#![no_main]

use libfuzzer_sys::fuzz_target;

// Mirrors handle_conn: heads larger than MAX_HEAD never reach
// rewrite_request in production, so the harness caps too (a panic
// above the cap would be a false crash the daemon cannot hit).
fuzz_target!(|data: &[u8]| {
  if data.len() > castellan_proxy::MAX_HEAD {
    return;
  }
  let parsed = castellan_proxy::fuzz_api::parse_connect(data);
  let host = parsed
    .as_ref()
    .map(|(h, _)| h.clone())
    .unwrap_or_else(|| "api.github.com".to_string());
  castellan_proxy::fuzz_api::rewrite_request(data, &host);
});
