//! Matching engine and file walker.

use std::fs;
use std::path::{Path, PathBuf};

use crate::entropy::shannon;
use crate::rules::{is_placeholder, Matcher, Rule, Severity};

pub struct Finding {
    pub file: String,
    pub line: usize,
    pub col: usize,
    pub rule: &'static str,
    pub hint: &'static str,
    pub severity: Severity,
    pub preview: String,
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".cache",
    "coverage",
    ".idea",
    ".vscode",
    "Pods",
    ".terraform",
];

const SKIP_EXT: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "webp", "bmp", "pdf", "zip", "gz", "tgz", "bz2", "xz",
    "7z", "rar", "tar", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "mov", "avi", "mkv",
    "wav", "so", "dylib", "dll", "exe", "class", "jar", "wasm", "o", "a", "pyc", "lockb",
];

const MAX_BYTES: u64 = 2 * 1024 * 1024;

pub fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'/')
}

fn take_token(hb: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < hb.len() && is_token_byte(hb[i]) {
        i += 1;
    }
    i
}

fn boundary_before(hb: &[u8], pos: usize) -> bool {
    pos == 0 || !is_token_byte(hb[pos - 1])
}

/// Keys may be embedded in longer identifiers: DB_PASSWORD, my_api_key.
/// Only a preceding letter or digit disqualifies a key match.
fn key_boundary_before(hb: &[u8], pos: usize) -> bool {
    pos == 0 || !hb[pos - 1].is_ascii_alphanumeric()
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

pub fn scan_line(file: &str, lineno: usize, line: &str, rules: &[Rule]) -> Vec<Finding> {
    let hb = line.as_bytes();
    let mut out: Vec<Finding> = Vec::new();

    for rule in rules {
        match &rule.matcher {
            Matcher::Literal(lit) => {
                let mut from = 0usize;
                while let Some(rel) = line[from..].find(lit) {
                    let pos = from + rel;
                    out.push(make(file, lineno, pos, pos + lit.len(), line, rule));
                    from = pos + lit.len();
                }
            }
            Matcher::Prefix { prefix, total_len } => {
                let mut from = 0usize;
                while let Some(rel) = line[from..].find(prefix) {
                    let pos = from + rel;
                    let end = pos + total_len;
                    if boundary_before(hb, pos)
                        && end <= hb.len()
                        && hb[pos + prefix.len()..end]
                            .iter()
                            .all(|b| is_token_byte(*b))
                        && (end == hb.len() || !is_token_byte(hb[end]))
                    {
                        out.push(make(file, lineno, pos, end, line, rule));
                    }
                    from = pos + 1;
                }
            }
            Matcher::PrefixMin { prefix, min_after } => {
                let mut from = 0usize;
                while let Some(rel) = line[from..].find(prefix) {
                    let pos = from + rel;
                    let after = pos + prefix.len();
                    if boundary_before(hb, pos) {
                        let end = take_token(hb, after);
                        if end - after >= *min_after {
                            out.push(make(file, lineno, pos, end, line, rule));
                        }
                    }
                    from = pos + 1;
                }
            }
            Matcher::KeyValue {
                keys,
                min_value,
                min_entropy,
            } => {
                for key in keys.iter() {
                    let mut from = 0usize;
                    while let Some(pos) = find_ci(line, key, from) {
                        from = pos + key.len();
                        if !key_boundary_before(hb, pos) {
                            continue;
                        }
                        let after_key = pos + key.len();
                        if after_key < hb.len() && is_word_byte(hb[after_key]) {
                            continue;
                        }
                        if let Some((vstart, vend)) = value_after(hb, after_key) {
                            let value = &line[vstart..vend];
                            if value.len() >= *min_value
                                && !is_placeholder(value)
                                && looks_like_secret(value)
                                && shannon(value) >= *min_entropy
                            {
                                out.push(make(file, lineno, vstart, vend, line, rule));
                            }
                        }
                    }
                }
            }
        }
    }

    out.sort_by_key(|f| (f.col, std::cmp::Reverse(f.severity.rank())));
    out.dedup_by_key(|f| f.col);
    out
}

/// Reject values that are clearly code, type names, or prose rather than a
/// credential. This is the difference between a usable tool and a noisy one.
pub fn looks_like_secret(v: &str) -> bool {
    if v.len() < 12 || v.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    let first = match v.chars().next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return false;
    }
    if v.contains("::") || v.contains("->") || v.contains('<') || v.contains('(') || v.contains(')')
    {
        return false;
    }
    let has_digit = v.chars().any(|c| c.is_ascii_digit());
    let has_alpha = v.chars().any(|c| c.is_ascii_alphabetic());
    let has_symbol = v
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, '-' | '_' | '.' | '/'));
    if !has_alpha || !(has_digit || has_symbol) {
        return false;
    }
    // CamelCase or snake_case identifiers are names, not secrets.
    let all_alnum = v.chars().all(|c| c.is_ascii_alphanumeric());
    if all_alnum && !has_digit {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if lower.ends_with("_token") || lower.ends_with("_key") || lower.ends_with("_secret") {
        return false;
    }
    true
}

fn value_after(hb: &[u8], mut i: usize) -> Option<(usize, usize)> {
    let skip_ws = |i: &mut usize| {
        while *i < hb.len() && (hb[*i] == b' ' || hb[*i] == b'\t') {
            *i += 1;
        }
    };
    skip_ws(&mut i);
    if i >= hb.len() {
        return None;
    }
    if matches!(hb[i], b'"' | b'\'') {
        i += 1;
    }
    skip_ws(&mut i);
    if i >= hb.len() {
        return None;
    }
    if hb[i] == b'=' {
        i += 1;
        if i < hb.len() && hb[i] == b'>' {
            i += 1;
        }
    } else if hb[i] == b':' {
        i += 1;
    } else {
        return None;
    }
    skip_ws(&mut i);
    if i < hb.len() && matches!(hb[i], b'"' | b'\'') {
        i += 1;
    }
    let start = i;
    while i < hb.len()
        && !matches!(
            hb[i],
            b' ' | b'\t' | b'"' | b'\'' | b',' | b';' | b'}' | b')'
        )
    {
        i += 1;
    }
    if i == start {
        None
    } else {
        Some((start, i))
    }
}

fn find_ci(hay: &str, needle: &str, from: usize) -> Option<usize> {
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() || hb.len() < nb.len() {
        return None;
    }
    let mut i = from;
    while i + nb.len() <= hb.len() {
        if hb[i..i + nb.len()]
            .iter()
            .zip(nb.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn make(file: &str, line: usize, start: usize, end: usize, text: &str, rule: &Rule) -> Finding {
    let raw = &text[start..end];
    Finding {
        file: file.to_string(),
        line,
        col: start + 1,
        rule: rule.id,
        hint: rule.hint,
        severity: rule.severity,
        preview: mask(raw),
    }
}

pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(6))
}

// ---------------------------------------------------------------- file walk

pub struct Ignore {
    patterns: Vec<(bool, String)>,
}

impl Ignore {
    pub fn load(root: &Path) -> Self {
        let mut patterns = Vec::new();
        if let Ok(text) = fs::read_to_string(root.join(".leakgateignore")) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (negated, pat) = match line.strip_prefix('!') {
                    Some(p) => (true, p.trim().to_string()),
                    None => (false, line.to_string()),
                };
                patterns.push((negated, pat));
            }
        }
        Ignore { patterns }
    }

    pub fn is_ignored(&self, rel: &str) -> bool {
        let mut ignored = false;
        for (negated, pat) in &self.patterns {
            let candidate = if pat.contains('/') {
                rel
            } else {
                basename(rel)
            };
            if glob_match(pat, candidate) {
                ignored = !negated;
            }
        }
        ignored
    }
}

fn basename(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob(pattern.as_bytes(), text.as_bytes())
}

fn glob(p: &[u8], t: &[u8]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    if p.starts_with(b"**") {
        let rest = &p[2..];
        let rest = rest.strip_prefix(b"/").unwrap_or(rest);
        for i in 0..=t.len() {
            if glob(rest, &t[i..]) {
                return true;
            }
        }
        return false;
    }
    match p[0] {
        b'*' => {
            let rest = &p[1..];
            for i in 0..=t.len() {
                if glob(rest, &t[i..]) {
                    return true;
                }
                if i < t.len() && t[i] == b'/' {
                    break;
                }
            }
            false
        }
        b'?' => !t.is_empty() && t[0] != b'/' && glob(&p[1..], &t[1..]),
        c => !t.is_empty() && t[0] == c && glob(&p[1..], &t[1..]),
    }
}

pub fn collect_files(roots: &[PathBuf], ignore: &Ignore, base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        if root.is_file() {
            out.push(root.clone());
        } else if root.is_dir() {
            walk(root, ignore, base, &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn walk(dir: &Path, ignore: &Ignore, base: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if name.starts_with('.')
            && name != ".env"
            && name != ".npmrc"
            && name != ".pypirc"
            && path.is_dir()
        {
            continue;
        }

        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(base) {
                if ignore.is_ignored(&rel.to_string_lossy()) {
                    continue;
                }
            }
            walk(&path, ignore, base, out);
            continue;
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if SKIP_EXT.contains(&ext.to_ascii_lowercase().as_str()) {
                continue;
            }
        }
        if let Ok(rel) = path.strip_prefix(base) {
            if ignore.is_ignored(&rel.to_string_lossy()) {
                continue;
            }
        }
        out.push(path);
    }
}

/// Read a file as text if it is small enough and does not look binary.
pub fn read_text(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > MAX_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub fn scan_file(path: &Path, display: &str, rules: &[Rule], ignore: &Ignore) -> Vec<Finding> {
    let text = match read_text(path) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.len() > 4000 {
            continue;
        }
        if line.contains("leakgate:allow") || line.contains("leakgate:ignore-line") {
            continue;
        }
        if ignore.is_ignored(display) {
            return out;
        }
        out.extend(scan_line(display, i + 1, line, rules));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RULES;

    fn hits(line: &str) -> Vec<&'static str> {
        scan_line("t", 1, line, RULES)
            .into_iter()
            .map(|f| f.rule)
            .collect()
    }

    #[test]
    fn detects_github_token() {
        let line = "const t = \"ghp_testfixture0000000000000000000000000000\";"; // leakgate:allow
        assert!(hits(line).contains(&"github-token"));
    }

    #[test]
    fn detects_aws_key() {
        let line = "aws_key=AKIAIOSFODNN7EXAMPLE"; // leakgate:allow
        assert!(hits(line).contains(&"aws-access-key"));
    }

    #[test]
    fn detects_stripe_live() {
        let line = "stripe = sk_live_test_fixture_do_not_use_000000"; // leakgate:allow
        assert!(hits(line).contains(&"stripe-live-key"));
    }

    #[test]
    fn skips_placeholder() {
        assert!(hits("api_key = \"your_api_key_here\"").is_empty());
    }

    #[test]
    fn skips_env_reference() {
        assert!(hits("password: process.env.DB_PASSWORD").is_empty());
    }

    #[test]
    fn detects_generic_secret() {
        let found = hits("password = \"Str0ng!Passw0rd#2024x\""); // leakgate:allow
        assert!(found.contains(&"hardcoded-password") || found.contains(&"generic-secret"));
    }

    #[test]
    fn detects_private_key_header() {
        let line = "-----BEGIN RSA PRIVATE KEY-----"; // leakgate:allow
        assert!(hits(line).contains(&"private-key"));
    }

    #[test]
    fn detects_database_url_without_spaces() {
        assert!(
            hits("database_url=postgres://admin:S3cr3tP4ss@db:5432/app").contains(&"database-url") // leakgate:allow
        ); // leakgate:allow
    }

    #[test]
    fn masks_most_of_the_value() {
        let m = mask("ghp_1234567890abcdef");
        assert!(m.starts_with("ghp_"));
        assert!(m.ends_with("cdef"));
        assert!(m.contains("******"));
    }

    #[test]
    fn glob_supports_double_star() {
        assert!(glob_match("**/*.env", "config/prod/.env"));
        assert!(glob_match("*.lock", "Cargo.lock"));
        assert!(!glob_match("*.lock", "dir/Cargo.lock"));
    }
}
