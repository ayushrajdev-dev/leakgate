mod entropy;
mod rules;
mod scan;

use std::env;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use rules::{Severity, RULES};
use scan::{collect_files, scan_file, Finding, Ignore};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mode = args.first().map(String::as_str);

    match mode {
        Some("scan") => cmd_scan(&args[1..]),
        Some("staged") => cmd_staged(&args[1..]),
        Some("install") => cmd_install(&args[1..]),
        Some("rules") => {
            print_rules();
            ExitCode::SUCCESS
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("leakgate {VERSION}");
            ExitCode::SUCCESS
        }
        Some("-h") | Some("--help") | Some("help") | None => {
            help();
            ExitCode::SUCCESS
        }
        Some(first) if first.starts_with('-') => {
            eprintln!("leakgate: unknown option {first} (try --help)");
            ExitCode::from(2)
        }
        Some(first) => {
            let mut rest = vec![first.to_string()];
            rest.extend_from_slice(&args[1..]);
            cmd_scan(&rest)
        }
    }
}

struct Opts {
    paths: Vec<String>,
    json: bool,
    color: bool,
    quiet: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            paths: Vec::new(),
            json: false,
            color: io::stdout().is_terminal(),
            quiet: false,
        }
    }
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    for a in args {
        match a.as_str() {
            "--json" => o.json = true,
            "--no-color" => o.color = false,
            "--color" => o.color = true,
            "-q" | "--quiet" => o.quiet = true,
            s if s.starts_with('-') && s != "-" => return Err(format!("unknown option {s}")),
            s => o.paths.push(s.to_string()),
        }
    }
    if o.paths.is_empty() {
        o.paths.push(".".to_string());
    }
    Ok(o)
}

fn cwd() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn cmd_scan(args: &[String]) -> ExitCode {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return fail(&e),
    };
    let base = cwd();
    let ignore = Ignore::load(&base);

    let mut findings = Vec::new();
    let mut stdin_files = 0usize;
    if opts.paths.iter().any(|p| p == "-") {
        let mut buf = String::new();
        let _ = io::stdin().read_to_string(&mut buf);
        stdin_files = 1;
        for (i, line) in buf.lines().enumerate() {
            findings.extend(scan::scan_line("<stdin>", i + 1, line, RULES));
        }
    }

    let roots: Vec<PathBuf> = opts
        .paths
        .iter()
        .filter(|p| p.as_str() != "-")
        .map(|p| {
            let pb = PathBuf::from(p);
            if pb.is_absolute() {
                pb
            } else {
                base.join(pb)
            }
        })
        .collect();

    let files = collect_files(&roots, &ignore, &base);
    for path in &files {
        let display = path
            .strip_prefix(&base)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());
        findings.extend(scan_file(path, &display, RULES, &ignore));
    }

    report(findings, files.len() + stdin_files, &opts)
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn cmd_staged(args: &[String]) -> ExitCode {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return fail(&e),
    };
    let base = cwd();
    let ignore = Ignore::load(&base);

    let listed = match git(
        &base,
        &["diff", "--cached", "--name-only", "--diff-filter=ACM"],
    ) {
        Ok(s) => s,
        Err(e) => return fail(&format!("not a git repository or git failed: {e}")),
    };

    let mut findings = Vec::new();
    let mut count = 0usize;
    for rel in listed.lines().filter(|l| !l.trim().is_empty()) {
        let path = base.join(rel);
        if !path.is_file() || ignore.is_ignored(rel) {
            continue;
        }
        count += 1;
        findings.extend(scan_file(&path, rel, RULES, &ignore));
    }

    if findings.is_empty() && !opts.quiet && !opts.json {
        eprintln!("leakgate: no secrets in {count} staged file(s)");
    }
    report(findings, count, &opts)
}

fn cmd_install(args: &[String]) -> ExitCode {
    let force = args.iter().any(|a| a == "--force" || a == "-f");
    let base = cwd();

    let root = match git(&base, &["rev-parse", "--show-toplevel"]) {
        Ok(s) => PathBuf::from(s.trim()),
        Err(_) => return fail("not inside a git repository"),
    };

    let hooks = match git(&root, &["rev-parse", "--git-path", "hooks"]) {
        Ok(p) => {
            let p = p.trim().to_string();
            let pb = PathBuf::from(&p);
            if pb.is_absolute() {
                pb
            } else {
                root.join(pb)
            }
        }
        Err(e) => return fail(&format!("cannot locate hooks directory: {e}")),
    };

    if let Err(e) = fs::create_dir_all(&hooks) {
        return fail(&format!("cannot create {}: {e}", hooks.display()));
    }

    let hook = hooks.join("pre-commit");
    if hook.exists() && !force {
        return fail(&format!(
            "{} already exists. Re-run with --force to replace it.",
            hook.display()
        ));
    }

    let exe = env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "leakgate".to_string());

    let script = format!(
        "#!/bin/sh\n# Installed by leakgate. Remove this file to disable.\nexec \"{exe}\" staged\n"
    );

    if let Err(e) = fs::write(&hook, script) {
        return fail(&format!("cannot write {}: {e}", hook.display()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&hook, fs::Permissions::from_mode(0o755));
    }

    println!("leakgate: hook installed at {}", hook.display());
    println!("Every commit now runs a secret scan. Bypass with git commit --no-verify.");
    ExitCode::SUCCESS
}

fn report(findings: Vec<Finding>, scanned: usize, opts: &Opts) -> ExitCode {
    if opts.json {
        let mut out = String::from("[");
        for (i, f) in findings.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"file\":\"{}\",\"line\":{},\"col\":{},\"rule\":\"{}\",\"hint\":\"{}\",\"severity\":\"{}\",\"preview\":\"{}\"}}",
                json_escape(&f.file),
                f.line,
                f.col,
                f.rule,
                json_escape(f.hint),
                f.severity.as_str(),
                json_escape(&f.preview)
            ));
        }
        out.push(']');
        println!("{out}");
    } else {
        let mut stdout = io::stdout().lock();
        for f in &findings {
            let color = if opts.color {
                match f.severity {
                    Severity::High => "\x1b[31m",
                    Severity::Medium => "\x1b[33m",
                }
            } else {
                ""
            };
            let reset = if opts.color { "\x1b[0m" } else { "" };
            let _ = writeln!(
                stdout,
                "{}{}:{}:{}{}  {}{}{}  {}  {}",
                if opts.color { "\x1b[2m" } else { "" },
                f.file,
                f.line,
                f.col,
                reset,
                color,
                f.severity.as_str(),
                reset,
                f.rule,
                f.preview
            );
        }
        if !opts.quiet && !findings.is_empty() {
            let high = findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count();
            eprintln!(
                "\nleakgate: {} finding(s) in {} file(s), {} high severity",
                findings.len(),
                scanned,
                high
            );
        }
    }

    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn print_rules() {
    println!("{:<24} {:<8} DESCRIPTION", "RULE", "SEVERITY");
    for r in RULES.iter() {
        println!("{:<24} {:<8} {}", r.id, r.severity.as_str(), r.hint);
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("leakgate: {msg}");
    ExitCode::from(2)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn help() {
    println!(
        "leakgate {VERSION} - block secrets before they are committed

USAGE
  leakgate scan [PATHS...] [OPTIONS]
  leakgate staged [OPTIONS]
  leakgate install [--force]
  leakgate rules

MODES
  scan      scan the given paths, default the current directory
  staged    scan files staged in git, for use as a pre-commit hook
  install   write .git/hooks/pre-commit so every commit is scanned
  rules     list every detection rule

OPTIONS
  --json       machine-readable output
  --no-color   disable ANSI colors
  -q, --quiet  suppress the summary line

EXIT CODES
  0  clean
  1  secrets found
  2  bad input

EXAMPLES
  leakgate scan .
  leakgate staged && git commit -m \"feat: add api\"
  leakgate install
  echo 'password = \"hunter2\"' | leakgate scan -

Suppress one line with a trailing comment: # leakgate:allow
Ignore paths in .leakgateignore, one glob per line. Prefix with ! to un-ignore.

Bypass a hook once with: git commit --no-verify"
    );
}
