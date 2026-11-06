//! Rule table. Every rule is a literal pattern plus a cheap validator, so the
//! whole scan stays under a millisecond per file.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    High,
    Medium,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Severity::High => 2,
            Severity::Medium => 1,
        }
    }
}

pub struct Rule {
    pub id: &'static str,
    pub hint: &'static str,
    pub severity: Severity,
    pub matcher: Matcher,
}

pub enum Matcher {
    /// Literal prefix, then a fixed total length of token characters.
    Prefix {
        prefix: &'static str,
        total_len: usize,
    },
    /// Literal prefix, then at least `min_after` token characters.
    PrefixMin {
        prefix: &'static str,
        min_after: usize,
    },
    /// Exact substring.
    Literal(&'static str),
    /// `key` followed by `:` or `=` and a value of at least `min_value`
    /// characters whose Shannon entropy is at least `min_entropy`.
    KeyValue {
        keys: &'static [&'static str],
        min_value: usize,
        min_entropy: f64,
    },
}

/// Keys where a literal value is almost certainly a credential.
pub const STRONG_KEYS: &[&str] = &[
    "password",
    "passwd",
    "client_secret",
    "private_key",
    "api_key",
    "apikey",
    "access_key",
];

pub const GENERIC_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "accesskey",
    "auth_key",
    "private_key",
    "credential",
];

pub static RULES: &[Rule] = &[
    Rule {
        id: "aws-access-key",
        hint: "AWS access key id",
        severity: Severity::High,
        matcher: Matcher::Prefix {
            prefix: "AKIA",
            total_len: 20,
        },
    },
    Rule {
        id: "aws-access-key-temp",
        hint: "AWS temporary access key id",
        severity: Severity::High,
        matcher: Matcher::Prefix {
            prefix: "ASIA",
            total_len: 20,
        },
    },
    Rule {
        id: "github-token",
        hint: "GitHub personal access token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "ghp_",
            min_after: 36,
        },
    },
    Rule {
        id: "github-token",
        hint: "GitHub token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "gho_",
            min_after: 36,
        },
    },
    Rule {
        id: "github-token",
        hint: "GitHub server token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "ghs_",
            min_after: 36,
        },
    },
    Rule {
        id: "github-pat",
        hint: "GitHub fine-grained token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "github_pat_",
            min_after: 60,
        },
    },
    Rule {
        id: "gitlab-token",
        hint: "GitLab personal access token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "glpat-",
            min_after: 20,
        },
    },
    Rule {
        id: "npm-token",
        hint: "npm publish token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "npm_",
            min_after: 36,
        },
    },
    Rule {
        id: "pypi-token",
        hint: "PyPI upload token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "pypi-AgEIcHlwaS5vcmc",
            min_after: 20,
        },
    },
    Rule {
        id: "stripe-live-key",
        hint: "Stripe live secret key",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "sk_live_",
            min_after: 24,
        },
    },
    Rule {
        id: "stripe-live-restricted",
        hint: "Stripe live restricted key",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "rk_live_",
            min_after: 24,
        },
    },
    Rule {
        id: "openai-key",
        hint: "OpenAI API key",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "sk-proj-",
            min_after: 40,
        },
    },
    Rule {
        id: "anthropic-key",
        hint: "Anthropic API key",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "sk-ant-",
            min_after: 24,
        },
    },
    Rule {
        id: "slack-token",
        hint: "Slack token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "xoxb-",
            min_after: 10,
        },
    },
    Rule {
        id: "slack-token",
        hint: "Slack token",
        severity: Severity::High,
        matcher: Matcher::PrefixMin {
            prefix: "xoxp-",
            min_after: 10,
        },
    },
    Rule {
        id: "google-api-key",
        hint: "Google API key",
        severity: Severity::High,
        matcher: Matcher::Prefix {
            prefix: "AIza",
            total_len: 39,
        },
    },
    Rule {
        id: "private-key",
        hint: "Private key block",
        severity: Severity::High,
        matcher: Matcher::Literal("-----BEGIN PRIVATE KEY-----"), // leakgate:allow
    },
    Rule {
        id: "private-key",
        hint: "RSA private key block",
        severity: Severity::High,
        matcher: Matcher::Literal("-----BEGIN RSA PRIVATE KEY-----"), // leakgate:allow
    },
    Rule {
        id: "private-key",
        hint: "OpenSSH private key block",
        severity: Severity::High,
        matcher: Matcher::Literal("-----BEGIN OPENSSH PRIVATE KEY-----"), // leakgate:allow
    },
    Rule {
        id: "discord-webhook",
        hint: "Discord webhook URL",
        severity: Severity::Medium,
        matcher: Matcher::PrefixMin {
            prefix: "https://discord.com/api/webhooks/",
            min_after: 20,
        },
    },
    Rule {
        id: "gcp-service-account",
        hint: "Google service account JSON",
        severity: Severity::High,
        matcher: Matcher::Literal("\"type\": \"service_account\""),
    },
    Rule {
        id: "aws-secret-key",
        hint: "AWS secret access key",
        severity: Severity::High,
        matcher: Matcher::KeyValue {
            keys: &[
                "aws_secret_access_key",
                "aws_secret_key",
                "secret_access_key",
            ],
            min_value: 30,
            min_entropy: 3.0,
        },
    },
    Rule {
        id: "hardcoded-password",
        hint: "Hardcoded password or key",
        severity: Severity::Medium,
        matcher: Matcher::KeyValue {
            keys: STRONG_KEYS,
            min_value: 12,
            min_entropy: 3.0,
        },
    },
    Rule {
        id: "generic-secret",
        hint: "Hardcoded credential",
        severity: Severity::Medium,
        matcher: Matcher::KeyValue {
            keys: GENERIC_KEYS,
            min_value: 16,
            min_entropy: 3.8,
        },
    },
    Rule {
        id: "database-url",
        hint: "Database URL with credentials",
        severity: Severity::High,
        matcher: Matcher::KeyValue {
            keys: &[
                "database_url",
                "db_url",
                "postgres_url",
                "mongodb_uri",
                "redis_url",
            ],
            min_value: 12,
            min_entropy: 2.0,
        },
    },
];

/// Values that are clearly placeholders, not credentials.
pub fn is_placeholder(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    if v.starts_with('$')
        || v.starts_with("{{")
        || v.starts_with('<')
        || v.starts_with('%')
        || v.starts_with("process.env")
        || v.starts_with("os.environ")
        || v.starts_with("env(")
        || v.starts_with("getenv")
        || v.starts_with("secret://")
        || v.starts_with("vault://")
    {
        return true;
    }
    [
        "example",
        "your_",
        "your-",
        "xxxx",
        "placeholder",
        "changeme",
        "redacted",
        "dummy",
        "sample",
        "test_",
    ]
    .iter()
    .any(|needle| v.contains(needle))
}
