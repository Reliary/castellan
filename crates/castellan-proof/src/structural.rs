use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralBlast {
  pub files: Vec<String>,
  pub touched_fns: Vec<String>,
  pub callees: Vec<String>,
  pub caller_hits: usize,
  pub scope_creep: bool,
}

const STOPWORDS: &[&str] = &[
  "abstract", "as", "assert", "async", "await", "boolean", "break", "byte", "case", "catch",
  "char", "class", "const", "continue", "crate", "debugger", "default", "delete", "do",
  "double", "echo", "else", "enum", "except", "extends", "false", "final", "finally", "float",
  "fn", "for", "from", "function", "global", "goto", "if", "impl", "implements", "import",
  "in", "instanceof", "int", "interface", "lambda", "let", "long", "loop", "match", "mod",
  "mut", "namespace", "new", "nil", "null", "package", "pass", "print", "println", "private",
  "protected", "pub", "public", "raise", "ref", "return", "self", "short", "sizeof", "static",
  "struct", "super", "switch", "synchronized", "template", "this", "throw", "throws", "trait",
  "true", "try", "type", "typedef", "typeof", "undefined", "use", "var", "virtual", "void",
  "volatile", "where", "while", "with", "yield",
];

const DEF_LEADS: &[&str] = &[
  "fn ", "async fn ", "unsafe fn ", "extern ", "pub ", "pub(crate) ", "pub(super) ", "def ",
  "async def ", "class ", "struct ", "enum ", "trait ", "impl ", "function ", "func ", "mod ",
];

const CODE_EXTS: &[&str] = &[
  "rs", "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "go", "java", "c", "h", "hpp", "cc",
  "cpp", "cxx", "cs", "rb", "php", "swift", "kt", "kts", "scala", "sh", "bash", "zsh", "fish",
  "pl", "pm", "lua", "r", "elm", "hs", "ml",
];

const SKIP_DIRS: &[&str] = &[
  ".git", "target", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".stria",
  ".reliary",
];

pub fn scan_idents(text: &str) -> Vec<(usize, &str)> {
  let bytes = text.as_bytes();
  let mut out = Vec::new();
  let mut i = 0;
  while i < bytes.len() {
    let b = bytes[i];
    if b.is_ascii_alphabetic() || b == b'_' {
      let start = i;
      i += 1;
      while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
      }
      if i - start >= 3 {
        out.push((start, &text[start..i]));
      }
    } else {
      i += 1;
    }
  }
  out
}

pub fn is_definition(phrase: &str, line: &str, match_start: usize) -> bool {
  let bytes = line.as_bytes();
  let end = match_start + phrase.len();
  if end >= bytes.len() {
    return false;
  }
  if match_start > 0 {
    let prev = bytes[match_start - 1];
    if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.' {
      return false;
    }
    let mut word_start = match_start;
    while word_start > 0 {
      let w = bytes[word_start - 1];
      if w.is_ascii_alphanumeric() || w == b'_' {
        break;
      }
      word_start -= 1;
    }
    let mut word_begin = word_start;
    while word_begin > 0 {
      let w = bytes[word_begin - 1];
      if !w.is_ascii_alphanumeric() && w != b'_' {
        break;
      }
      word_begin -= 1;
    }
    let preceding = std::str::from_utf8(&bytes[word_begin..word_start]).unwrap_or("");
    if preceding == "new" || preceding == "import" {
      return false;
    }
  }
  if next_struct_char(line, end) == Some(b'(')
    || next_struct_char(line, end) == Some(b'<')
    || next_struct_char(line, end) == Some(b'[')
    || next_struct_char(line, end) == Some(b'=')
    || next_struct_char(line, end) == Some(b':')
    || next_struct_char(line, end) == Some(b'{')
  {
    return true;
  }
  if let Some(pos) = struct_char_pos(line, end) {
    let bytes = line.as_bytes();
    if bytes[pos] == b'-' && pos + 1 < bytes.len() && bytes[pos + 1] == b'>' {
      return true;
    }
  }
  false
}

fn struct_char_pos(line: &str, mut pos: usize) -> Option<usize> {
  let bytes = line.as_bytes();
  loop {
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
      pos += 1;
    }
    if pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
      while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
        pos += 1;
      }
      continue;
    }
    break;
  }
  if pos < bytes.len() {
    Some(pos)
  } else {
    None
  }
}

fn next_struct_char(line: &str, pos: usize) -> Option<u8> {
  struct_char_pos(line, pos).map(|p| line.as_bytes()[p])
}

fn sig_name(line: &str) -> String {
  let trimmed = line.trim_start();
  if !DEF_LEADS.iter().any(|l| trimmed.starts_with(l)) {
    return String::new();
  }
  for (pos, word) in scan_idents(line) {
    if STOPWORDS.binary_search(&word).is_ok() {
      continue;
    }
    if is_definition(word, line, pos) {
      return word.to_string();
    }
  }
  String::new()
}

fn is_def_line(line: &str, name: &str) -> bool {
  let trimmed = line.trim_start();
  if !DEF_LEADS.iter().any(|l| trimmed.starts_with(l)) {
    return false;
  }
  match line.find(name) {
    Some(p) => is_definition(name, line, p),
    None => false,
  }
}

pub fn code_file(path: &str) -> bool {
  match path.rsplit('.').next() {
    Some(ext) => {
      let lower = ext.to_ascii_lowercase();
      CODE_EXTS.contains(&lower.as_str())
    }
    None => false,
  }
}

struct FnRange {
  name: String,
  start: usize,
  end: usize,
}

fn brace_fns(lines: &[&str]) -> Vec<FnRange> {
  let mut out = Vec::new();
  if lines.is_empty() {
    return out;
  }
  let content = lines.join("\n");
  let bytes = content.as_bytes();
  let mut line_starts: Vec<usize> = Vec::with_capacity(lines.len());
  let mut off = 0;
  for line in lines {
    line_starts.push(off);
    off += line.len() + 1;
  }
  let line_of = |pos: usize| -> usize {
    match line_starts.binary_search(&pos) {
      Ok(i) => i,
      Err(i) => i.saturating_sub(1),
    }
  };
  let sigs: Vec<String> = lines.iter().map(|l| sig_name(l)).collect();
  let mut depth: i64 = 0;
  let mut stack: Vec<(usize, i64, String)> = Vec::new();
  let mut last_sig: Option<(String, usize)> = None;
  let mut last_sig_line = 0;
  let mut i = 0;
  let mut line_comment = false;
  let mut block_comment = false;
  let mut str_delim: Option<u8> = None;
  let mut raw_open = false;
  let mut raw_hashes = 0;
  let mut escaped = false;
  let mut cur_line = 0;
  while i < bytes.len() {
    let b = bytes[i];
    if b == b'\n' {
      if !sigs[cur_line].is_empty() {
        last_sig = Some((sigs[cur_line].clone(), cur_line));
        last_sig_line = cur_line;
      }
      cur_line += 1;
      line_comment = false;
      i += 1;
      continue;
    }
    if line_comment {
      i += 1;
      continue;
    }
    if block_comment {
      if b == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
        block_comment = false;
        i += 2;
      } else {
        i += 1;
      }
      continue;
    }
    if let Some(d) = str_delim {
      if escaped {
        escaped = false;
      } else if b == b'\\' {
        escaped = true;
      } else if b == d {
        str_delim = None;
      }
      i += 1;
      continue;
    }
    if raw_open {
      if b == b'"' {
        let mut k = i + 1;
        let mut ok = true;
        for _ in 0..raw_hashes {
          if k < bytes.len() && bytes[k] == b'#' {
            k += 1;
          } else {
            ok = false;
            break;
          }
        }
        if ok {
          raw_open = false;
          i = k;
          continue;
        }
      }
      i += 1;
      continue;
    }
    if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
      line_comment = true;
      i += 2;
      continue;
    }
    if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
      block_comment = true;
      i += 2;
      continue;
    }
    if b == b'"' || b == b'`' {
      str_delim = Some(b);
      i += 1;
      continue;
    }
    if b == b'r' {
      let mut j = i + 1;
      let mut h = 0;
      while j < bytes.len() && bytes[j] == b'#' {
        h += 1;
        j += 1;
      }
      if j < bytes.len() && bytes[j] == b'"' {
        raw_open = true;
        raw_hashes = h;
        i = j + 1;
        continue;
      }
    }
    if b == b'{' {
      depth += 1;
      let ln = line_of(i);
      let mut name = sigs.get(ln).cloned().unwrap_or_default();
      if name.is_empty() {
        if let Some((ref n, sl)) = last_sig {
          if ln.saturating_sub(sl) <= 3 {
            name = n.clone();
          }
        }
      }
      void_last_sig_check(&mut last_sig, &mut last_sig_line, ln);
      stack.push((ln, depth, name));
      i += 1;
      continue;
    }
    if b == b'}' {
      depth -= 1;
      let ln = line_of(i);
      while stack.last().map(|s| s.1 > depth).unwrap_or(false) {
        let (start, _, name) = stack.pop().unwrap();
        if !name.is_empty() {
          out.push(FnRange { name, start, end: ln });
        }
      }
      i += 1;
      continue;
    }
    i += 1;
  }
  let last = lines.len().saturating_sub(1);
  while let Some((start, _, name)) = stack.pop() {
    if !name.is_empty() {
      out.push(FnRange { name, start, end: last });
    }
  }
  out
}

fn void_last_sig_check(
  last_sig: &mut Option<(String, usize)>,
  last_sig_line: &mut usize,
  ln: usize,
) {
  if ln.saturating_sub(*last_sig_line) <= 3 {
    *last_sig = None;
  }
}

fn indent_width(line: &str) -> usize {
  let mut w = 0;
  for b in line.bytes() {
    if b == b' ' {
      w += 1;
    } else if b == b'\t' {
      w += 8;
    } else {
      break;
    }
  }
  w
}

fn indent_fns(content: &str) -> Vec<(String, String)> {
  let lines: Vec<&str> = content.lines().collect();
  let mut defs: Vec<(String, usize, usize)> = Vec::new();
  for (i, line) in lines.iter().enumerate() {
    let trimmed = line.trim_start();
    let rest = trimmed
      .strip_prefix("async def ")
      .or_else(|| trimmed.strip_prefix("def "))
      .unwrap_or("");
    let name = scan_idents(rest).into_iter().next().map(|(_, w)| w.to_string());
    let Some(name) = name else { continue };
    if name.is_empty() {
      continue;
    }
    defs.push((name, i, indent_width(line)));
  }
  let mut out = Vec::new();
  for (name, start, ind) in &defs {
    let mut end = lines.len().saturating_sub(1);
    for (j, l) in lines.iter().enumerate().skip(start + 1) {
      if l.trim().is_empty() {
        continue;
      }
      if indent_width(l) <= *ind {
        end = j.saturating_sub(1);
        break;
      }
    }
    let body = lines[*start..=end].join("\n");
    out.push((name.clone(), body));
  }
  out
}

fn extract_functions(content: &str, path: &str) -> Vec<(String, String)> {
  if !code_file(path) {
    return Vec::new();
  }
  if content.contains('{') {
    let lines: Vec<&str> = content.lines().collect();
    let mut bodies: HashMap<String, String> = HashMap::new();
    for r in brace_fns(&lines) {
      let hi = r.end.min(lines.len().saturating_sub(1));
      if r.start > hi {
        continue;
      }
      let body = lines[r.start..=hi].join("\n");
      let e = bodies.entry(r.name).or_default();
      e.push_str(&body);
      e.push('\n');
    }
    bodies.into_iter().collect()
  } else {
    indent_fns(content)
  }
}

fn fnv(body: &str) -> u64 {
  let mut h: u64 = 0xcbf29ce484222325;
  for b in body.bytes() {
    h ^= b as u64;
    h = h.wrapping_mul(0x100000001b3);
  }
  h
}

fn fn_map(content: &str, path: &str) -> HashMap<String, u64> {
  let mut m: HashMap<String, String> = HashMap::new();
  for (n, b) in extract_functions(content, path) {
    let e = m.entry(n).or_default();
    e.push_str(&b);
    e.push('\n');
  }
  m.into_iter().map(|(k, v)| (k, fnv(&v))).collect()
}

fn touched_names(orig: &str, new: &str, path: &str) -> Vec<String> {
  let mo = fn_map(orig, path);
  let mn = fn_map(new, path);
  let mut keys: HashSet<&str> = HashSet::new();
  for k in mo.keys() {
    keys.insert(k.as_str());
  }
  for k in mn.keys() {
    keys.insert(k.as_str());
  }
  let mut out = Vec::new();
  for k in keys {
    if mo.get(k) != mn.get(k) {
      out.push(k.to_string());
    }
  }
  out.sort();
  out
}

fn fn_bodies(content: &str, path: &str) -> HashMap<String, String> {
  let mut m: HashMap<String, String> = HashMap::new();
  for (n, b) in extract_functions(content, path) {
    let e = m.entry(n).or_default();
    e.push_str(&b);
    e.push('\n');
  }
  m
}

pub fn extract_callees(body: &str) -> Vec<String> {
  let mut set: HashSet<String> = HashSet::new();
  for line in body.lines() {
    let bytes = line.as_bytes();
    for (pos, word) in scan_idents(line) {
      if STOPWORDS.binary_search(&word).is_ok() {
        continue;
      }
      if pos > 0 && bytes[pos - 1] == b'.' {
        continue;
      }
      if next_struct_char(line, pos + word.len()) != Some(b'(') {
        continue;
      }
      set.insert(word.to_string());
    }
  }
  let mut v: Vec<String> = set.into_iter().collect();
  v.sort();
  v
}

fn count_callers(project: &Path, names: &[String]) -> usize {
  if names.is_empty() {
    return 0;
  }
  let wanted: HashSet<&str> = names.iter().map(|s| s.as_str()).collect();
  let mut hits = 0usize;
  let mut files_seen = 0usize;
  let mut stack = vec![project.to_path_buf()];
  while let Some(dir) = stack.pop() {
    let entries = match std::fs::read_dir(&dir) {
      Ok(e) => e,
      Err(_) => continue,
    };
    for entry in entries.flatten() {
      if hits >= 2000 {
        return hits;
      }
      let path = entry.path();
      if path.is_dir() {
        if let Some(n) = path.file_name().and_then(|s| s.to_str()) {
          if SKIP_DIRS.contains(&n) {
            continue;
          }
          if n.starts_with('.') {
            continue;
          }
        }
        stack.push(path);
        continue;
      }
      if files_seen >= 2000 {
        continue;
      }
      let len = entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
      if len > 524288 {
        continue;
      }
      let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => continue,
      };
      files_seen += 1;
      for line in content.lines() {
        let mut seen_line: HashSet<&str> = HashSet::new();
        for (pos, word) in scan_idents(line) {
          if !wanted.contains(word) {
            continue;
          }
          if !seen_line.insert(word) {
            continue;
          }
          if is_def_line(line, word) {
            continue;
          }
          let bytes = line.as_bytes();
          if pos > 0 && bytes[pos - 1] == b'.' {
            continue;
          }
          if next_struct_char(line, pos + word.len()) != Some(b'(') {
            continue;
          }
          hits += 1;
          if hits >= 2000 {
            return hits;
          }
        }
      }
    }
  }
  hits
}

pub fn blast_for_session(project: &Path, upper: &Path) -> StructuralBlast {
  let changed = castellan_ledger::diff_upper(upper).unwrap_or_default();
  let mut files: Vec<String> = Vec::new();
  let mut touched: HashSet<String> = HashSet::new();
  let mut callees: HashSet<String> = HashSet::new();
  let mut code_files = 0usize;
  let mut bodies: HashMap<String, String> = HashMap::new();
  for c in &changed {
    if c.kind != "file" && c.kind != "deleted" {
      continue;
    }
    files.push(c.path.clone());
    if !code_file(&c.path) {
      continue;
    }
    code_files += 1;
    let orig = std::fs::read_to_string(project.join(&c.path)).unwrap_or_default();
    let new = if c.kind == "deleted" {
      String::new()
    } else {
      std::fs::read_to_string(upper.join(&c.path)).unwrap_or_default()
    };
    for name in touched_names(&orig, &new, &c.path) {
      touched.insert(name);
    }
    for (n, b) in fn_bodies(&new, &c.path) {
      bodies.entry(n).or_insert(b);
    }
    for (n, b) in fn_bodies(&orig, &c.path) {
      bodies.entry(n).or_insert(b);
    }
  }
  for name in touched.iter() {
    if let Some(body) = bodies.get(name) {
      for cal in extract_callees(body) {
        callees.insert(cal);
      }
    }
  }
  let mut touched_v: Vec<String> = touched.into_iter().collect();
  touched_v.sort();
  let caller_hits = count_callers(project, &touched_v);
  let mut callees_v: Vec<String> = callees.into_iter().collect();
  callees_v.sort();
  files.sort();
  touched_v.truncate(100);
  callees_v.truncate(100);
  files.truncate(100);
  let scope_creep = touched_v.len() > 3 || code_files > 3;
  StructuralBlast { files, touched_fns: touched_v, callees: callees_v, caller_hits, scope_creep }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn stopwords_sorted_for_binary_search() {
    for w in STOPWORDS.windows(2) {
      assert!(w[0] < w[1], "stopwords out of order at {}", w[0]);
    }
  }

  #[test]
  fn brace_two_fns_modify_one() {
    let orig = "fn alpha() {\n return 1;\n}\nfn beta(x: u32) {\n return x;\n}\n";
    let new = "fn alpha() {\n return 1;\n}\nfn beta(x: u32) {\n return x + 1;\n}\n";
    assert_eq!(touched_names(orig, new, "a.rs"), vec!["beta".to_string()]);
  }

  #[test]
  fn brace_new_file_marks_all() {
    let touched = touched_names("", "fn gamma() {\n return 2;\n}\n", "b.rs");
    assert_eq!(touched, vec!["gamma".to_string()]);
  }

  #[test]
  fn brace_deleted_file_marks_all() {
    let touched = touched_names("fn gone() {\n return 0;\n}\n", "", "c.rs");
    assert_eq!(touched, vec!["gone".to_string()]);
  }

  #[test]
  fn python_indent_modify() {
    let orig = "def foo():\n return 1\n\ndef bar():\n return 2\n";
    let new = "def foo():\n return 1\n\ndef bar():\n return 3\n";
    assert_eq!(touched_names(orig, new, "a.py"), vec!["bar".to_string()]);
  }

  #[test]
  fn noncode_files_have_no_functions() {
    let touched = touched_names("hello: world\n", "hello: world changed\n", "README.md");
    assert!(touched.is_empty());
  }

  #[test]
  fn callees_skip_keywords_and_dotted() {
    let body = "fn outer() {\n if x {\n foo(y);\n obj.method(z);\n return bar(w);\n }\n}";
    let c = extract_callees(body);
    assert!(c.contains(&"foo".to_string()));
    assert!(c.contains(&"bar".to_string()));
    assert!(!c.contains(&"if".to_string()));
    assert!(!c.contains(&"return".to_string()));
    assert!(!c.contains(&"method".to_string()));
  }

  #[test]
  fn def_line_detection() {
    assert!(is_def_line("fn beta(x: u32) {", "beta"));
    assert!(!is_def_line("  let y = beta(3);", "beta"));
    assert!(is_def_line("def gamma():", "gamma"));
  }

  fn tmp_pair(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let ts = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_nanos())
      .unwrap_or(0);
    let base = std::env::temp_dir().join(format!("castellan-struct-{tag}-{ts}"));
    let proj = base.join("proj");
    let upper = base.join("upper");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&upper).unwrap();
    (proj, upper)
  }

  #[test]
  fn session_blast_small_change_no_creep() {
    let (proj, upper) = tmp_pair("small");
    std::fs::write(proj.join("a.rs"), "fn alpha() {\n return 1;\n}\nfn beta(x: u32) {\n return x;\n}\n").unwrap();
    std::fs::write(proj.join("c.rs"), "fn user() {\n let y = beta(3);\n}\n").unwrap();
    std::fs::write(upper.join("a.rs"), "fn alpha() {\n return 1;\n}\nfn beta(x: u32) {\n return x + 1;\n}\n").unwrap();
    std::fs::write(upper.join("b.rs"), "fn gamma() {\n return 2;\n}\n").unwrap();
    let blast = blast_for_session(&proj, &upper);
    assert_eq!(blast.files.len(), 2);
    assert!(blast.touched_fns.contains(&"beta".to_string()));
    assert!(blast.touched_fns.contains(&"gamma".to_string()));
    assert!(!blast.scope_creep);
    assert!(blast.caller_hits >= 1);
    let _ = std::fs::remove_dir_all(base_of(&proj));
  }

  #[test]
  fn session_blast_many_files_is_creep() {
    let (proj, upper) = tmp_pair("creep");
    for i in 0..4 {
      let name = format!("f{i}.rs");
      std::fs::write(proj.join(&name), "fn base() {\n return 0;\n}\n").unwrap();
      std::fs::write(upper.join(&name), "fn base() {\n return 1;\n}\n").unwrap();
    }
    let blast = blast_for_session(&proj, &upper);
    assert!(blast.scope_creep);
    let _ = std::fs::remove_dir_all(base_of(&proj));
  }

  #[test]
  fn session_blast_docs_only_no_creep() {
    let (proj, upper) = tmp_pair("docs");
    std::fs::write(proj.join("README.md"), "hello\n").unwrap();
    std::fs::write(upper.join("README.md"), "hello changed\n").unwrap();
    let blast = blast_for_session(&proj, &upper);
    assert!(blast.touched_fns.is_empty());
    assert!(!blast.scope_creep);
    let _ = std::fs::remove_dir_all(base_of(&proj));
  }

  fn base_of(proj: &std::path::Path) -> std::path::PathBuf {
    proj.parent().unwrap().to_path_buf()
  }
}
