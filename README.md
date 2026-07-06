# Verdict

**AI code, human confidence.**

A CLI tool for validating AI-generated code quality through static analysis, security scanning, and AI-powered semantic review.

<!-- Badges -->
[![CI](https://github.com/wwh-dghh/verdict/actions/workflows/ci.yml/badge.svg)](https://github.com/wwh-dghh/verdict/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/verdict.svg)](https://crates.io/crates/verdict)
[![Docs](https://img.shields.io/badge/docs-rs-blue.svg)](https://docs.rs/verdict)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org)

🇨🇳 [中文文档](README_CN.md)

## Demo

```
$ verdict check ./src

════════════════════════════════════════════════════════════
  Verdict — AI Code Verification Report
════════════════════════════════════════════════════════════

  Files analyzed: 3
  Total findings: 5
  ✗ 2 error(s)
  ⚠ 3 warning(s)

  📊 Scores for src/auth.py: 62/100 (security:50!)
  📊 Scores for src/api.js: 85/100
  📊 Scores for src/utils.rs: 95/100

  ──────────────────────────────────────────────────
  src/auth.py:
  src/auth.py [ERROR]  SEC003 Possible hardcoded secret detected
    → Use environment variables or a secrets manager
  src/auth.py [WARN]  SEC004 Weak hash function (MD5) detected
    → Use SHA-256 or bcrypt for password hashing
```

## Why Verdict?

AI coding assistants are great at generating code — but how do you know it's **safe**, **correct**, and **well-written**? Verdict bridges the gap between "it runs" and "it's production-ready."

## Features

- **Static Analysis** — Integrates Ruff (Python), Biome/Oxlint (JS/TS) for code quality checks
- **Security Scanning** — Detects SQL injection, XSS, hardcoded secrets, weak crypto, and more
- **AI Semantic Review** — Optional LLM-as-Judge for deeper code quality analysis
- **Multi-dimensional Scoring** — Security, code quality, performance, testing, AI risk
- **Three Output Formats** — Terminal (colorized), JSON, SARIF (CI/CD compatible)
- **CI/CD Gating** — Configurable thresholds to pass/fail builds
- **Incremental** — Git diff-aware mode to only analyze changed files
- **Extensible** — Plugin system for custom rules

## Install

### From crates.io

```bash
cargo install verdict
```

### From source

```bash
git clone https://github.com/wwh-dghh/verdict.git
cd verdict
cargo build --release
cp target/release/verdict /usr/local/bin/
```

## Quick Start

```bash
# Analyze a directory
verdict check ./src

# Enable AI semantic review (requires LLM config)
verdict check ./src --explain

# Output as JSON for CI/CD
verdict check ./src -f json

# Show available security rules
verdict rules

# Generate config template
verdict init > .verdict.yaml
```

## Configuration

Create a `.verdict.yaml` file:

```yaml
targets: ["./src"]
languages: [python, javascript]
security_scan: true
ai_review: false
output: terminal
diff_mode: false
ignore:
  - ".git"
  - "node_modules"
  - "__pycache__"
thresholds:
  security: 70
  code_quality: 60
  overall: 50
```

## Plugins

Custom security rules can be defined as JSON files in `./plugins/` or `~/.verdict/plugins/`:

```json
{
  "name": "my-rules",
  "version": "1.0.0",
  "rules": [
    {
      "code": "CUSTOM001",
      "name": "No console.log",
      "pattern": "console\\.log\\s*\\(",
      "severity": "warning",
      "message": "console.log should not be in production",
      "languages": ["javascript", "typescript"],
      "exclude": ["**/test/**"]
    }
  ]
}
```

Generate a template: `verdict init` (creates `plugins/example-rules.json`)

## Pre-commit Hook

```bash
# Install
verdict hooks

# Uninstall
verdict hooks --uninstall
```

The hook runs `verdict check --diff` before each commit. Skip with `git commit --no-verify`.

## VS Code Extension

Install the `verdict` extension from the VS Code marketplace, or build from source:

```bash
cd vscode-verdict
npm install
npm run package
# Install the .vsix file in VS Code
```

## Architecture

```
CLI (clap)
  │
  ▼
Pipeline Orchestrator
  ├── Preprocess  → File discovery & language detection
  ├── Lint        → Ruff / Biome / Oxlint / golangci-lint / clippy
  ├── Security    → Pattern-based vulnerability scanning + plugins
  ├── Semantic    → LLM-as-Judge (optional)
  ├── Aggregate   → Multi-dimensional scoring
  └── Report      → Terminal / JSON / SARIF

Plugin System
  ├── ~/.verdict/plugins/  → User-level custom rules
  └── ./plugins/           → Project-level custom rules

VS Code Extension
  └── vscode-verdict/      → Diagnostics, auto-check on save
```

## Security Rules

| Code   | Description                        | Severity |
|--------|------------------------------------|----------|
| SEC001 | Potential SQL injection            | Error    |
| SEC002 | Potential XSS                      | Error/Warn|
| SEC003 | Hardcoded secrets                  | Error    |
| SEC004 | Weak cryptography (MD5, DES)       | Warn     |
| SEC005 | Debug logging leaks                | Warn     |
| SEC006 | Unsafe eval()                      | Error    |
| SEC007 | Command injection                  | Error    |

## Roadmap

- [x] Core pipeline architecture
- [x] Security scanning with 7 built-in rules
- [x] Terminal, JSON, SARIF output
- [x] LLM-as-Judge semantic review
- [x] `verdict init` / `verdict rules` commands
- [x] Git diff-aware incremental analysis (`--diff`)
- [x] Plugin system for custom security rules (JSON-based)
- [x] Pre-commit hook integration (`verdict hooks`)
- [x] VS Code extension (`vscode-verdict/`)
- [x] Go (golangci-lint) and Rust (clippy) linter support
- [ ] Plugin marketplace
- [ ] WASM plugin runtime (for advanced plugins)
- [ ] GitHub Actions integration
- [ ] Team collaboration features

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
