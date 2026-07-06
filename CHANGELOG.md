# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Plugin marketplace
- WASM plugin runtime (for advanced plugins)
- Team collaboration features

### Changed
- Nothing yet

### Fixed
- Nothing yet

## [0.2.1] - 2026-07-06

### Added
- GitHub Actions integration
  - Composite action: `.github/actions/verdict/action.yml`
  - Auto-installs verdict binary (detects OS/arch)
  - Supports: targets, format, diff, explain, fail-on-error, version
  - Outputs: findings count, errors count, pass/fail result
  - Example workflow: `.github/workflows/example-verdict-check.yml`

## [0.2.0] - 2026-07-06

### Added
- Git diff incremental analysis (`--diff` flag)
- Plugin system for custom security rules (JSON-based)
  - Load from `~/.verdict/plugins/` and `./plugins/`
  - Language filters, file include/exclude patterns
  - `verdict init` generates example plugin
- Pre-commit hook integration (`verdict hooks` / `verdict hooks --uninstall`)
- VS Code extension (`vscode-verdict/`)
  - Auto-check on save
  - Diagnostics in Problems panel
  - Commands: Check Workspace, Check Current File, Show Rules
- Go linter support via golangci-lint
- Rust linter support via cargo clippy
- 51 unit tests (was 33)

### Changed
- SecurityStage now loads plugin rules alongside builtin rules
- LintStage auto-detects golangci-lint and cargo

## [0.1.0] - 2025-07-05

### Added
- Initial release of Verdict
