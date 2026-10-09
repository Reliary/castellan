//! P21.5: shell completions. A hand-written single source, printed by
//! `castellan completions <shell>`. The verb list lives here (one table)
//! because the CLI is hand-rolled (no clap), so a generator that reads
//! the parser does not exist — this table is the generator's input, and
//! `test/doc-truth-verbs.py` still pins the usage lines against the
//! match arms. When a verb is added, it is added here too.

use std::io::Write;

/// Every top-level verb `castellan` accepts, in usage order. `--version`
/// and `-V` are flags; included in suggestions for completeness.
pub const VERBS: &[&str] = &[
    "status",
    "preflight",
    "watch",
    "freeze",
    "thaw",
    "kill",
    "spawn",
    "launch",
    "audit",
    "diff",
    "undo",
    "keep",
    "adopt",
    "bless",
    "siblings",
    "campaign",
    "canary",
    "trust",
    "cert",
    "verify",
    "replay",
    "radar",
    "drill",
    "channels",
    "trace",
    "policycheck",
    "memory",
    "voice",
    "proxy",
    "service",
    "uninstall",
    "gc",
    "init",
    "doctor",
    "completions",
    "version",
];

fn bash_script() -> String {
    let words = VERBS.join(" ");
    format!(
        r#"# castellan bash completions. Source this file or install to
# /usr/share/bash-completion/completions/castellan.
_castellan() {{
  local cur prev words verbs
  COMPREPLY=()
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"
  verbs="{words}"
  case "$prev" in
    castellan)
      COMPREPLY=( $(compgen -W "$verbs" -- "$cur") )
      return 0
      ;;
    completions)
      COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
      return 0
      ;;
    service)
      COMPREPLY=( $(compgen -W "install uninstall stop status logs" -- "$cur") )
      return 0
      ;;
  esac
  case "${{COMP_WORDS[1]}}" in
    freeze|thaw|kill|adopt|audit|cert|replay|radar|trace)
      COMPREPLY=( $(compgen -W "--kill-after-m" -- "$cur") )
      return 0
      ;;
    bless)
      COMPREPLY=( $(compgen -W "request approve reject show" -- "$cur") )
      return 0
      ;;
  esac
  return 0
}}
complete -F _castellan castellan
"#
    )
}

fn zsh_script() -> String {
    let words = VERBS.join(" ");
    format!(
        r#"#compdef castellan
# castellan zsh completions. Install to a directory in $fpath as _castellan.
_castellan() {{
  local -a verbs
  verbs=({words})
  if (( CURRENT == 2 )); then
    _describe 'verb' verbs
    return
  fi
  case "$words[2]" in
    completions) _values 'shell' bash zsh fish ;;
    service) _values 'subcommand' install uninstall stop status logs ;;
    bless) _values 'subcommand' request approve reject show ;;
    freeze|thaw|kill|adopt|audit|cert|replay|radar|trace) _values 'flag' --kill-after-m ;;
  esac
}}
compdef _castellan castellan
"#
    )
}

fn fish_script() -> String {
    let mut lines = String::from("# castellan fish completions. Install to ~/.config/fish/completions/castellan.fish.\n");
    lines.push_str("complete -c castellan -f\n");
    for v in VERBS {
        lines.push_str(&format!("complete -c castellan -n '__fish_use_subcommand' -a '{v}'\n"));
    }
    lines.push_str("complete -c castellan -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'\n");
    lines.push_str("complete -c castellan -n '__fish_seen_subcommand_from service' -a 'install uninstall stop status logs'\n");
    lines.push_str("complete -c castellan -n '__fish_seen_subcommand_from bless' -a 'request approve reject show'\n");
    lines.push_str("complete -c castellan -n '__fish_seen_subcommand_from freeze thaw kill adopt audit cert replay radar trace' -l kill-after-m -r\n");
    lines
}

pub fn run_completions(args: &[String]) -> ! {
    let shell = args.first().map(|s| s.as_str()).unwrap_or("bash");
    let script = match shell {
        "bash" => bash_script(),
        "zsh" => zsh_script(),
        "fish" => fish_script(),
        other => {
            eprintln!("usage: castellan completions <bash|zsh|fish>  (unknown shell: {other})");
            std::process::exit(2);
        }
    };
    let mut out = std::io::stdout();
    let _ = out.write_all(script.as_bytes());
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_script_names_every_verb() {
        for (shell, script) in [
            ("bash", bash_script()),
            ("zsh", zsh_script()),
            ("fish", fish_script()),
        ] {
            for v in VERBS {
                assert!(
                    script.contains(v),
                    "{shell} completion missing verb {v}"
                );
            }
        }
    }

    #[test]
    fn verb_table_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for v in VERBS {
            assert!(seen.insert(*v), "duplicate verb {v}");
        }
    }
}
