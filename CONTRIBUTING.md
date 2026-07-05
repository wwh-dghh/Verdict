# Contributing to Verdict

Thank you for your interest in contributing to Verdict!

## Getting Started

### Prerequisites

- Rust 1.75+ (installed via [rustup](https://rustup.rs/))
- Cargo

### Setup

```bash
# Clone the repo
git clone https://github.com/wwh-dghh/verdict.git
cd verdict

# Build
cargo build

# Run tests
cargo test

# Run the CLI
cargo run -- check ./your-project
```

## Project Structure

```
verdict/
├── src/
│   ├── main.rs          # CLI entry point (clap)
│   ├── models.rs         # Core data types
│   ├── pipeline.rs       # Pipeline orchestration
│   ├── lint.rs           # Linter adapters (Ruff, Biome, Oxlint)
│   ├── security.rs       # Security pattern scanner
│   ├── semantic.rs       # LLM-as-Judge semantic review
│   ├── report.rs         # Terminal/JSON/SARIF reporters
│   └── config.rs         # Config loader
├── testdata/             # Test fixtures
├── Cargo.toml
└── README.md
```

## How to Contribute

### 1. Report Bugs

Use the [GitHub Issues](https://github.com/wwh-dghh/verdict/issues) to report bugs. Include:
- Steps to reproduce
- Expected vs actual behavior
- Your OS and Verdict version

### 2. Suggest Features

We welcome feature requests! Please describe:
- The problem you're trying to solve
- How Verdict could help
- Any alternative solutions you've considered

### 3. Submit Code

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run `cargo fmt` and `cargo clippy`
5. Commit with a clear message
6. Push and open a Pull Request

### 4. Add New Security Rules

See `src/security.rs` — each rule is a `SecurityPattern` with:
- A regex pattern
- Severity (Error/Warning)
- A code (SECXXX) and descriptive message
- An optional suggestion

### 5. Add a New Linter

See `src/lint.rs` — implement the `LintAdapter` trait:

```rust
struct MyLinterAdapter;

#[async_trait::async_trait]
impl LintAdapter for MyLinterAdapter {
    fn name(&self) -> &str { "my-linter" }
    async fn lint_file(&self, path: &PathBuf) -> Result<Vec<Finding>> {
        // Run your linter as a subprocess
        // Parse its output into Finding structs
    }
}
```

## Coding Standards

- Follow `cargo fmt`
- Run `cargo clippy -- -D warnings`
- Keep functions small and focused
- Add comments for non-obvious logic
- Write tests for new features

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Tag release: `git tag v0.x.x`
4. Push: `git push && git push --tags`
5. Publish: `cargo publish`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
