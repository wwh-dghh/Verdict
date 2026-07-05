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
                let findings = adapter
                    .lint_file(&r.path)
                    .await
                    .unwrap_or_default();
                r.findings.extend(findings);
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

        if linters.is_empty() {
            tracing::warn!("no linters found (ruff/bun/oxlint); install one for lint checks");
        }

        Self { linters }
    }
}

/// Trait for lint adapter implementations
#[async_trait::async_trait]
#[expect(dead_code)]
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
        #[expect(dead_code)]
        column: usize,
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
