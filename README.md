# leakgate

Block secrets before they are committed. One 393 KB binary, no dependencies, 13 detection rules plus entropy checks.

```console
$ leakgate installed as a pre-commit hook

$ git commit -m "feat: add stripe"
src/config.ts:12:11  high  stripe-live-key  sk_l******0000
src/auth.py:2:12     high  openai-key       sk-p******EFGH

leakgate: 2 finding(s) in 3 file(s), 2 high severity
```

Commit rejected. Fix the line, or `git commit --no-verify` to bypass once.

```sh
curl -fsSL https://raw.githubusercontent.com/ayushrajdev-dev/leakgate/main/install.sh | sh
```

---

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/ayushrajdev-dev/leakgate/main/install.sh | sh
```

Cargo: `cargo install --git https://github.com/ayushrajdev-dev/leakgate`

Then wire it into one repository:

```sh
cd your-repo
leakgate install
```

That writes `.git/hooks/pre-commit`. Every commit scans the staged files and exits non-zero on a finding.

Already using [pre-commit](https://pre-commit.com)? Add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ayushrajdev-dev/leakgate
    rev: v1.0.0
    hooks:
      - id: leakgate
```

### GitHub Actions

```yaml
- uses: ayushrajdev-dev/leakgate@v1
```

Fails the check when a secret reaches a pull request.

---

## Usage

```
leakgate scan [PATHS...]      # scan paths, default: current directory
leakgate staged               # scan staged files, hook mode
leakgate install [--force]    # write .git/hooks/pre-commit
leakgate rules                # list every detection rule
```

| Flag | Meaning |
|---|---|
| `--json` | machine-readable output, one object per finding |
| `--no-color` | disable ANSI colors |
| `-q, --quiet` | suppress the summary line |

Exit codes: `0` clean, `1` findings, `2` bad input.

```sh
leakgate scan .                       # whole repo
leakgate scan src/ config/            # two directories
cat .env | leakgate scan -             # stdin
leakgate scan . --json | jq length     # count findings
```

---

## Rules

`leakgate rules` prints this table from the binary, so it never drifts.

| Rule | Severity | Catches |
|---|---|---|
| `aws-access-key` | high | `AKIA…` access key ids |
| `aws-access-key-temp` | high | `ASIA…` temporary keys |
| `aws-secret-key` | high | `aws_secret_access_key` assignments |
| `github-token` | high | `ghp_`, `gho_`, `ghs_` tokens |
| `github-pat` | high | `github_pat_` fine-grained tokens |
| `gitlab-token` | high | `glpat-` tokens |
| `npm-token` | high | `npm_` publish tokens |
| `pypi-token` | high | `pypi-AgEIcHlwaS5vcmc` tokens |
| `stripe-live-key` | high | `sk_live_` keys |
| `stripe-live-restricted` | high | `rk_live_` keys |
| `openai-key` | high | `sk-proj-` keys |
| `anthropic-key` | high | `sk-ant-` keys |
| `slack-token` | high | `xoxb-`, `xoxp-` tokens |
| `google-api-key` | high | `AIza…` keys |
| `private-key` | high | PEM private key blocks |
| `gcp-service-account` | high | service account JSON |
| `database-url` | high | `postgres://user:pass@`, `mongodb_uri` |
| `discord-webhook` | medium | Discord webhook URLs |
| `hardcoded-password` | medium | `password`, `api_key`, `access_key` with a literal value |
| `generic-secret` | medium | any `key: value` where the value has high entropy |

### False positives

Measured on the Rust crate registry: **21,146 files, 2 findings, both real test fixtures.** No model, no heuristics that need tuning.

The scanner rejects values that are clearly not credentials:

- `process.env.X`, `os.environ[...]`, `${VAR}`, `{{ var }}`, `<placeholder>`
- anything containing `example`, `your_`, `xxxx`, `changeme`, `dummy`, `sample`
- identifiers and type names: `token: Handle<T>`, `:Increasing`, `&Registered`

### Suppression

Whole files or directories, in `.leakgateignore` at the repo root. One glob per line, `!` to un-ignore:

```
*.md
vendor/**
!vendor/README.md
```

A single line:

```python
api_key = "..."  # leakgate:allow
```

`leakgate:ignore-line` works too.

---

## Speed

| Target | Files | Time |
|---|---|---|
| small project | 40 | 10 ms |
| Rust crate registry | 21,146 | 34 s |

Single static binary, 393 KB, no runtime. Skips `.git`, `node_modules`, `target`, `dist`, `vendor`, binaries, and files over 2 MB. Reads each file once, scans line by line, never sends anything over the network.

---

## What it does not do

- It is not a replacement for server-side scanning. A secret that was pushed before the hook existed is still leaked; rotate it.
- It does not scan git history. `leakgate scan` reads the working tree, `leakgate staged` reads the index.
- It will not catch a secret split across lines or one that only appears after a runtime transform.

---

## Build

```sh
cargo test        # 13 unit tests
cargo clippy --all-targets
cargo build --release
```

---

## License

MIT. See [LICENSE](LICENSE).
