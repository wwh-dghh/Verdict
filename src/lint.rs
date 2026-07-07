//! Lint adapter modules — wraps Ruff, Biome, Oxlint as subprocesses.

use crate::models::*;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use tokio::process::Command;

use super::pipeline::Stage;

/// Lint stage that delegates to installed linters
pub struct LintStage {
    linters: Vec<Box<dyn LintAdapter>>,
}

#[async_trait::async_trait]
impl Stage for LintStage {
    fn name(&self) -> &str {
        "lint"
    }

    async fn execute(&self, input: &[AnalysisResult]) -> Result<Vec<AnalysisResult>> {
        let mut results = input.to_vec();

        for adapter in &self.linters {
            for r in &mut results {
                match adapter.lint_file(&r.path).await {
                    Ok(findings) => {
                        r.findings.extend(findings);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "linter '{}' failed on {}: {}",
                            adapter.name(),
                            r.path.display(),
                            e
                        );
                    }
                }
            }
        }

        Ok(results)
    }
}

impl LintStage {
    pub fn new() -> Self {
        let mut linters: Vec<Box<dyn LintAdapter>> = Vec::new();

        if which::which("ruff").is_ok() {
            linters.push(Box::new(RuffAdapter));
        }
        if which::which("bun").is_ok() {
            linters.push(Box::new(BiomeAdapter));
        }
        if which::which("oxlint").is_ok() {
            linters.push(Box::new(OxlintAdapter));
        }
        if which::which("golangci-lint").is_ok() {
            linters.push(Box::new(GolangciLintAdapter));
        }
        // cargo clippy is always available if rustup is installed
        if which::which("cargo").is_ok() {
            linters.push(Box::new(ClippyAdapter));
        }

        if linters.is_empty() {
            tracing::warn!(
                "no linters found; install ruff, bun, oxlint, golangci-lint, or use cargo clippy"
            );
        }

        Self { linters }
    }
}

/// Trait for lint adapter implementations
#[async_trait::async_trait]
pub trait LintAdapter: Send + Sync {
    fn name(&self) -> &str;
    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>>;
}

// ─── Ruff Adapter ────────────────────────────────────────────────────

struct RuffAdapter;

#[async_trait::async_trait]
impl LintAdapter for RuffAdapter {
    fn name(&self) -> &str {
        "ruff"
    }

    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let output = Command::new("ruff")
            .arg("check")
            .arg("--output-format")
            .arg("json")
            .arg(path)
            .output()
            .await
            .with_context(|| "failed to run ruff")?;

        let findings = parse_ruff_output(&output.stdout, path);
        Ok(findings)
    }
}

fn parse_ruff_output(output: &[u8], file: &Path) -> Vec<Finding> {
    #[derive(Deserialize)]
    struct RuffDiagnostic {
        code: String,
        message: String,
        location: RuffLocation,
    }

    #[derive(Deserialize)]
    struct RuffLocation {
        row: usize,
    }

    #[derive(Deserialize)]
    struct RuffReport {
        diagnostics: Vec<RuffDiagnostic>,
    }

    let Some(report) = serde_json::from_slice::<RuffReport>(output).ok() else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for diag in report.diagnostics {
        let severity = match diag.code.as_str() {
            "F401" | "F841" | "E" | "F" => Severity::Error,
            "W" | "B" | "SIM" => Severity::Warning,
            _ => Severity::Info,
        };

        findings.push(Finding::new(
            Category::Lint,
            severity,
            diag.code,
            diag.message,
            file.to_path_buf(),
            Some(diag.location.row),
        ));
    }

    findings
}

// ─── Biome Adapter ───────────────────────────────────────────────────

struct BiomeAdapter;

#[async_trait::async_trait]
impl LintAdapter for BiomeAdapter {
    fn name(&self) -> &str {
        "biome"
    }

    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>> {
        // Try `biome check` directly first
        let output = Command::new("biome")
            .arg("check")
            .arg("--json")
            .arg(path)
            .output()
            .await;

        let findings = if let Ok(output) = output {
            parse_biome_output(&output.stdout, path)
        } else {
            // Fallback: bun x @biomejs/biome check --files-ignore-unknown <path>
            let output = Command::new("bun")
                .arg("x")
                .arg("@biomejs/biome")
                .arg("check")
                .arg("--files-ignore-unknown")
                .arg(path)
                .output()
                .await;

            if let Ok(output) = output {
                parse_biome_output(&output.stdout, path)
            } else {
                Vec::new()
            }
        };

        Ok(findings)
    }
}

fn parse_biome_output(_output: &[u8], _file: &Path) -> Vec<Finding> {
    // TODO: Parse Biome JSON output format
    Vec::new()
}

// ─── Oxlint Adapter ──────────────────────────────────────────────────

struct OxlintAdapter;

#[async_trait::async_trait]
impl LintAdapter for OxlintAdapter {
    fn name(&self) -> &str {
        "oxlint"
    }

    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let output = Command::new("oxlint")
            .arg("--format")
            .arg("json")
            .arg(path)
            .output()
            .await
            .with_context(|| "failed to run oxlint")?;

        let findings = parse_oxlint_output(&output.stdout, path);
        Ok(findings)
    }
}

fn parse_oxlint_output(_output: &[u8], _file: &Path) -> Vec<Finding> {
    // TODO: Parse Oxlint JSON output format
    Vec::new()
}

// ─── Golangci-lint Adapter ───────────────────────────────────────────

struct GolangciLintAdapter;

#[async_trait::async_trait]
impl LintAdapter for GolangciLintAdapter {
    fn name(&self) -> &str {
        "golangci-lint"
    }

    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let output = Command::new("golangci-lint")
            .arg("run")
            .arg("--out-format")
            .arg("json")
            .arg("--issues-exit-code=0")
            .arg(path)
            .output()
            .await
            .with_context(|| "failed to run golangci-lint")?;

        let findings = parse_golangci_output(&output.stdout, path);
        Ok(findings)
    }
}

fn parse_golangci_output(output: &[u8], _file: &Path) -> Vec<Finding> {
    #[derive(Deserialize)]
    struct GolangciIssue {
        text: String,
        from_linter: String,
        severity: Option<String>,
        location: Option<GolangciLocation>,
    }

    #[derive(Deserialize)]
    struct GolangciLocation {
        line: Option<usize>,
    }

    #[derive(Deserialize)]
    struct GolangciReport {
        issues: Option<Vec<GolangciIssue>>,
    }

    let Some(report) = serde_json::from_slice::<GolangciReport>(output).ok() else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for issue in report.issues.unwrap_or_default() {
        let severity = match issue.severity.as_deref() {
            Some("error") => Severity::Error,
            Some("warning") => Severity::Warning,
            _ => Severity::Info,
        };

        let line = issue.location.as_ref().and_then(|l| l.line).unwrap_or(1);

        findings.push(Finding::new(
            Category::Lint,
            severity,
            issue.from_linter.clone(),
            issue.text,
            _file.to_path_buf(),
            Some(line),
        ));
    }

    findings
}

// ─── Clippy Adapter ──────────────────────────────────────────────────

struct ClippyAdapter;

#[async_trait::async_trait]
impl LintAdapter for ClippyAdapter {
    fn name(&self) -> &str {
        "clippy"
    }

    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>> {
        // Only run clippy on .rs files
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            return Ok(Vec::new());
        }

        let output = Command::new("cargo")
            .arg("clippy")
            .arg("--message-format=json")
            .arg("--")
            .arg("-W")
            .arg("clippy::all")
            .current_dir(path.parent().unwrap_or(path))
            .output()
            .await
            .with_context(|| "failed to run cargo clippy")?;

        let findings = parse_clippy_output(&output.stdout, path);
        Ok(findings)
    }
}

fn parse_clippy_output(output: &[u8], file: &Path) -> Vec<Finding> {
    let text = String::from_utf8_lossy(output);
    let mut findings = Vec::new();

    for line in text.lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        // cargo clippy JSON messages have "reason": "compiler-message"
        if msg.get("reason").and_then(|r| r.as_str()) != Some("compiler-message") {
            continue;
        }

        let Some(message) = msg.get("message") else {
            continue;
        };

        let Some(text) = message.get("message").and_then(|m| m.as_str()) else {
            continue;
        };

        let code = message
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|c| c.as_str())
            .unwrap_or("CLIPPY");

        let level = message
            .get("level")
            .and_then(|l| l.as_str())
            .unwrap_or("warning");

        let severity = match level {
            "error" => Severity::Error,
            "warning" => Severity::Warning,
            _ => Severity::Info,
        };

        let line_num = message
            .get("spans")
            .and_then(|s| s.as_array())
            .and_then(|spans| spans.first())
            .and_then(|span| span.get("line_start"))
            .and_then(|l| l.as_u64())
            .map(|l| l as usize);

        findings.push(Finding::new(
            Category::Lint,
            severity,
            code.to_string(),
            text.to_string(),
            file.to_path_buf(),
            line_num,
        ));
    }

    findings
}
