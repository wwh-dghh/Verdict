//! Report generation — terminal, JSON, and SARIF output formats.

use crate::models::*;
use anyhow::Result;
use colored::Colorize;

/// Generates a report from analysis results
pub struct Reporter {
    format: OutputFormat,
}

impl Reporter {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    /// Generate report and return as string
    pub fn generate(&self, result: &PipelineResult) -> Result<String> {
        match self.format {
            OutputFormat::Terminal => Ok(self.render_terminal(result)),
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&result)?;
                Ok(json)
            }
            OutputFormat::Sarif => Ok(self.render_sarif(result)),
        }
    }

    /// Print directly to stdout
    pub fn print(&self, result: &PipelineResult) -> Result<()> {
        let output = self.generate(result)?;
        println!("{}", output);
        Ok(())
    }

    // ─── Terminal Renderer ───────────────────────────────────────────

    fn render_terminal(&self, result: &PipelineResult) -> String {
        let mut buf = String::new();

        // Header
        let sep = "═".repeat(60);
        buf.push_str(&format!("\n{sep}"));
        buf.push_str("\n  Verdict — AI Code Verification Report");
        buf.push_str(&format!("\n{sep}\n"));

        // Summary
        let total = result.total_findings;
        let errors = result
            .results
            .iter()
            .flat_map(|r| &r.findings)
            .filter(|f| f.is_error())
            .count();
        let warnings = result
            .results
            .iter()
            .flat_map(|r| &r.findings)
            .filter(|f| f.severity == Severity::Warning)
            .count();

        buf.push_str(&format!("\n  Files analyzed: {}", result.results.len()));
        buf.push_str(&format!("\n  Total findings: {total}"));

        if errors > 0 {
            let err_str = format!("{} error(s)", errors);
            buf.push_str(&format!("\n  ✗ {}", err_str.red().bold()));
        }
        if warnings > 0 {
            let warn_str = format!("{} warning(s)", warnings);
            buf.push_str(&format!("\n  ⚠ {}", warn_str.yellow().bold()));
        }
        if total == 0 {
            buf.push_str("\n  ✓ No issues found!");
        }

        // Scores
        for r in &result.results {
            if let Some(scores) = &r.scores {
                buf.push_str(&format!("\n\n  📊 Scores for {}:", r.path.display()));

                let overall_str = format!("{:.0}/100", scores.overall);
                let overall_str = if scores.overall >= 80.0 {
                    overall_str.green().bold().to_string()
                } else if scores.overall >= 60.0 {
                    overall_str.yellow().bold().to_string()
                } else {
                    overall_str.red().bold().to_string()
                };
                buf.push_str(&format!(" {overall_str}"));

                if scores.security < 70.0 {
                    buf.push_str(
                        &format!(" (security:{:.0}!)", scores.security)
                            .red()
                            .to_string(),
                    );
                }
            }
        }

        // Detailed findings
        for r in &result.results {
            if !r.findings.is_empty() {
                buf.push_str(&format!("\n\n  {}", "─".repeat(50)).dimmed().to_string());
                buf.push_str(&format!("\n  {}:", r.path.display()).bold().to_string());

                for f in &r.findings {
                    let sev_str = match f.severity {
                        Severity::Error => format!(" [{}] ", "ERROR".red().bold()),
                        Severity::Warning => format!(" [{}] ", "WARN".yellow().bold()),
                        Severity::Info => format!(" [{}] ", "INFO".dimmed()),
                    };

                    let line_str = f.line.map(|l| format!(":{}", l)).unwrap_or_default();

                    buf.push_str(&format!(
                        "  {}{}{} {} {}\n",
                        f.file.display(),
                        line_str.dimmed(),
                        sev_str,
                        f.code.bold(),
                        f.message
                    ));

                    if let Some(sugg) = &f.suggestion {
                        buf.push_str(&format!("    → {}\n", sugg.dimmed()));
                    }
                }
            }
        }

        buf
    }

    // ─── SARIF Renderer ──────────────────────────────────────────────

    fn render_sarif(&self, result: &PipelineResult) -> String {
        let mut sarif = serde_json::Map::new();
        sarif.insert("version".into(), "2.1.0".into());
        sarif.insert(
            "runs".into(),
            serde_json::Value::Array(vec![serde_json::json!({
                "tool": {
                    "driver": {
                        "name": "verdict",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/verdict-tool/verdict",
                        "rules": self.collect_rules(result)
                    }
                },
                "results": self.collect_results(result)
            })]),
        );

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|e| {
            tracing::error!("failed to serialize SARIF output: {}", e);
            "{}".to_string()
        })
    }

    fn collect_rules(&self, result: &PipelineResult) -> Vec<serde_json::Value> {
        let mut codes = std::collections::HashSet::new();
        for r in &result.results {
            for f in &r.findings {
                codes.insert(&f.code);
            }
        }
        codes
            .iter()
            .map(|code| {
                serde_json::json!({
                    "id": code,
                    "shortDescription": {"text": code}
                })
            })
            .collect()
    }

    fn collect_results(&self, result: &PipelineResult) -> Vec<serde_json::Value> {
        result.results.iter().flat_map(|r| {
            r.findings.iter().map(move |f| {
                serde_json::json!({
                    "ruleId": f.code,
                    "level": match f.severity {
                        Severity::Error => "error",
                        Severity::Warning => "warning",
                        Severity::Info => "note",
                    },
                    "message": {"text": f.message},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": r.path.to_string_lossy().to_string()},
                            "region": f.line.map(|l| serde_json::json!({"startLine": l})).unwrap_or_default()
                        }
                    }]
                })
            })
        }).collect()
    }
}
