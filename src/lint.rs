//! Lint adapter modules — wraps Ruff, Biome, Oxlint as subprocesses.

use crate::models::{AnalysisResult, Category, Finding, Severity};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use super::pipeline::Stage;

/// Map a diagnostic severity string to our Severity enum
fn map_severity(s: Option<&str>, default: Severity) -> Severity {
    match s {
        Some("error") => Severity::Error,
        Some("warning") => Severity::Warning,
        _ => default,
    }
}

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
    /// Create a new lint stage, auto-detecting available linters on the system
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
    fn name(&self) -> &'static str;
    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>>;
}

// ─── Ruff Adapter ────────────────────────────────────────────────────

struct RuffAdapter;

#[async_trait::async_trait]
impl LintAdapter for RuffAdapter {
    fn name(&self) -> &'static str {
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
            "F401" | "F841" => Severity::Error,
            c if c.starts_with('E') || c.starts_with('F') => Severity::Error,
            c if c.starts_with('W') || c.starts_with('B') || c.starts_with("SIM") => {
                Severity::Warning
            }
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
    fn name(&self) -> &'static str {
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
            // biome emits JSON to stdout even on non-zero exit, so always try to parse first
            let parsed = parse_biome_output(&output.stdout, path);
            if !parsed.is_empty() || output.status.success() {
                parsed
            } else {
                // biome produced no findings and exited non-zero — try bun fallback
                let output2 = Command::new("bun")
                    .arg("x")
                    .arg("@biomejs/biome")
                    .arg("check")
                    .arg("--files-ignore-unknown")
                    .arg(path)
                    .output()
                    .await;

                if let Ok(output2) = output2 {
                    if output2.status.success() {
                        parse_biome_output(&output2.stdout, path)
                    } else {
                        tracing::warn!(
                            "biome check failed: {}",
                            String::from_utf8_lossy(&output2.stderr)
                        );
                        Vec::new()
                    }
                } else {
                    tracing::warn!(
                        "biome check failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        Ok(findings)
    }
}

fn parse_biome_output(output: &[u8], file: &Path) -> Vec<Finding> {
    #[derive(Deserialize)]
    struct BiomeDiagnostic {
        message: String,
        code: Option<String>,
        severity: Option<String>,
        location: Option<BiomeLocation>,
    }

    #[derive(Deserialize)]
    struct BiomeLocation {
        line: Option<usize>,
    }

    #[derive(Deserialize)]
    struct BiomeReport {
        diagnostics: Vec<BiomeDiagnostic>,
    }

    let Some(report) = serde_json::from_slice::<BiomeReport>(output).ok() else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for diag in report.diagnostics {
        let severity = map_severity(diag.severity.as_deref(), Severity::Error);

        let line = diag.location.and_then(|l| l.line);
        let code = diag.code.unwrap_or_else(|| "BIOME".to_string());

        findings.push(Finding::new(
            Category::Lint,
            severity,
            code,
            diag.message,
            file.to_path_buf(),
            line,
        ));
    }

    findings
}

// ─── Oxlint Adapter ──────────────────────────────────────────────────

struct OxlintAdapter;

#[async_trait::async_trait]
impl LintAdapter for OxlintAdapter {
    fn name(&self) -> &'static str {
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

fn parse_oxlint_output(output: &[u8], file: &Path) -> Vec<Finding> {
    #[derive(Deserialize)]
    struct OxlintResult {
        line: Option<usize>,
        #[allow(dead_code)]
        column: Option<usize>,
        severity: Option<String>,
        message: String,
        code: Option<String>,
    }

    #[derive(Deserialize)]
    struct OxlintReport {
        results: Vec<OxlintResult>,
    }

    let Some(report) = serde_json::from_slice::<OxlintReport>(output).ok() else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for diag in report.results {
        let severity = map_severity(diag.severity.as_deref(), Severity::Error);

        let code = diag.code.unwrap_or_else(|| "OXLLINT".to_string());

        findings.push(Finding::new(
            Category::Lint,
            severity,
            code,
            diag.message,
            file.to_path_buf(),
            diag.line,
        ));
    }

    findings
}

// ─── Golangci-lint Adapter ───────────────────────────────────────────

struct GolangciLintAdapter;

#[async_trait::async_trait]
impl LintAdapter for GolangciLintAdapter {
    fn name(&self) -> &'static str {
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

fn parse_golangci_output(output: &[u8], file: &Path) -> Vec<Finding> {
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
        let severity = map_severity(issue.severity.as_deref(), Severity::Info);

        let line = issue.location.as_ref().and_then(|l| l.line).unwrap_or(1);

        findings.push(Finding::new(
            Category::Lint,
            severity,
            issue.from_linter.clone(),
            issue.text,
            file.to_path_buf(),
            Some(line),
        ));
    }

    findings
}

// ─── Clippy Adapter ──────────────────────────────────────────────────

struct ClippyAdapter;

impl ClippyAdapter {
    /// Resolve the Cargo.toml directory from a file path by walking up the tree
    fn find_cargo_root(file_path: &Path) -> PathBuf {
        let start = file_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        for dir in std::iter::successors(Some(start.as_path()), |p| p.parent()) {
            if dir.join("Cargo.toml").exists() {
                return dir.to_path_buf();
            }
            if dir.as_os_str().is_empty() || dir.parent() == Some(dir) {
                break;
            }
        }

        tracing::warn!(
            "could not find Cargo.toml in ancestor directories of {}; \
             falling back to parent directory",
            file_path.display()
        );
        file_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

#[async_trait::async_trait]
impl LintAdapter for ClippyAdapter {
    fn name(&self) -> &'static str {
        "clippy"
    }

    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>> {
        // Only run clippy on .rs files
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            return Ok(Vec::new());
        }

        let cargo_root = Self::find_cargo_root(path);

        let output = Command::new("cargo")
            .arg("clippy")
            .arg("--message-format=json")
            .arg("--")
            .arg("-W")
            .arg("clippy::all")
            .current_dir(&cargo_root)
            .output()
            .await
            .with_context(|| format!("failed to run cargo clippy in {}", cargo_root.display()))?;

        let findings = parse_clippy_output(&output.stdout, path);
        Ok(findings)
    }
}

fn parse_clippy_output(output: &[u8], target_file: &Path) -> Vec<Finding> {
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

        // Filter: only include findings for the target file
        let file_names: Vec<_> = message
            .get("spans")
            .and_then(|s| s.as_array())
            .map(|spans| {
                spans
                    .iter()
                    .filter_map(|span| span.get("file_name").and_then(|f| f.as_str()))
                    .collect()
            })
            .unwrap_or_default();

        if !file_names.iter().any(|f| {
            // Compare using same_file semantics with fallback to basename matching
            // to handle cases where the file doesn't exist or canonicalize fails
            let target_canonical = target_file.canonicalize().ok();
            let file_canonical = Path::new(f).canonicalize().ok();
            target_canonical == file_canonical
                || target_file.file_name() == Path::new(f).file_name()
        }) {
            continue;
        }

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
            target_file.to_path_buf(),
            line_num,
        ));
    }

    findings
}
