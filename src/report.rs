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
                        "informationUri": "https://github.com/wwh-dghh/verdict",
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
                codes.insert((&f.code, &f.message));
            }
        }
        codes
            .iter()
            .map(|(code, desc)| {
                serde_json::json!({
                    "id": code,
                    "shortDescription": {"text": code},
                    "fullDescription": {"text": desc}
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_pipeline_result(
        findings: Vec<Finding>,
        scores: Option<QualityScores>,
    ) -> PipelineResult {
        PipelineResult {
            stages_completed: vec![PipelineStage::Preprocess, PipelineStage::Lint],
            results: vec![AnalysisResult {
                path: PathBuf::from("src/test.rs"),
                language: Some(Language::Rust),
                findings,
                scores,
                duration_ms: 100,
            }],
            total_findings: 0,
            failed_thresholds: vec![],
            exit_code: 0,
        }
    }

    fn make_finding(severity: Severity, code: &str, message: &str) -> Finding {
        Finding::new(
            Category::Lint,
            severity,
            code,
            message,
            PathBuf::from("src/test.rs"),
            Some(10),
        )
    }

    #[test]
    fn test_reporter_new() {
        let reporter = Reporter::new(OutputFormat::Terminal);
        // Should not panic
        let _ = reporter;
    }

    #[test]
    fn test_generate_json_format() {
        let reporter = Reporter::new(OutputFormat::Json);
        let result = make_pipeline_result(vec![], None);
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("results").is_some());
        assert!(parsed.get("total_findings").is_some());
    }

    #[test]
    fn test_generate_sarif_format() {
        let reporter = Reporter::new(OutputFormat::Sarif);
        let finding = make_finding(Severity::Warning, "W001", "unused variable");
        let result = make_pipeline_result(vec![finding], None);
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed.get("runs").is_some());
        let runs = parsed["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        assert!(runs[0].get("tool").is_some());
        assert!(runs[0].get("results").is_some());
    }

    #[test]
    fn test_generate_terminal_format_no_findings() {
        let reporter = Reporter::new(OutputFormat::Terminal);
        let result = make_pipeline_result(vec![], None);
        let output = reporter.generate(&result).unwrap();
        assert!(output.contains("Verdict"));
        assert!(output.contains("Files analyzed:"));
        assert!(output.contains("No issues found"));
    }

    #[test]
    fn test_generate_terminal_with_errors() {
        let reporter = Reporter::new(OutputFormat::Terminal);
        let finding = make_finding(Severity::Error, "E001", "syntax error");
        let result = make_pipeline_result(vec![finding], None);
        let output = reporter.generate(&result).unwrap();
        assert!(output.contains("E001"));
        assert!(output.contains("syntax error"));
        assert!(output.contains("ERROR"));
    }

    #[test]
    fn test_generate_terminal_with_warnings() {
        let reporter = Reporter::new(OutputFormat::Terminal);
        let finding = make_finding(Severity::Warning, "W001", "unused import");
        let result = make_pipeline_result(vec![finding], None);
        let output = reporter.generate(&result).unwrap();
        assert!(output.contains("W001"));
        assert!(output.contains("unused import"));
        assert!(output.contains("WARN"));
    }

    #[test]
    fn test_generate_terminal_with_scores() {
        let reporter = Reporter::new(OutputFormat::Terminal);
        let scores = QualityScores::new(95.0, 80.0, 90.0, 70.0, 85.0);
        let result = make_pipeline_result(vec![], Some(scores));
        let output = reporter.generate(&result).unwrap();
        assert!(output.contains("Scores for"));
        assert!(output.contains("/100"));
    }

    #[test]
    fn test_sarif_contains_rule_info() {
        let reporter = Reporter::new(OutputFormat::Sarif);
        let finding1 = make_finding(Severity::Error, "SEC001", "SQL injection");
        let finding2 = make_finding(Severity::Warning, "SEC001", "SQL injection");
        let result = make_pipeline_result(vec![finding1, finding2], None);
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let rules = &parsed["runs"][0]["tool"]["driver"]["rules"];
        // Same rule code should appear only once
        let rules_array = rules.as_array().unwrap();
        assert_eq!(rules_array.len(), 1);
        assert_eq!(rules_array[0]["id"], "SEC001");
    }

    #[test]
    fn test_sarif_severity_mapping() {
        let reporter = Reporter::new(OutputFormat::Sarif);
        let findings = vec![
            make_finding(Severity::Error, "E001", "error test"),
            make_finding(Severity::Warning, "W001", "warning test"),
            make_finding(Severity::Info, "I001", "info test"),
        ];
        let result = make_pipeline_result(findings, None);
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        let levels: Vec<&str> = results
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        assert!(levels.contains(&"error"));
        assert!(levels.contains(&"warning"));
        assert!(levels.contains(&"note"));
    }

    #[test]
    fn test_sarif_with_line_numbers() {
        let reporter = Reporter::new(OutputFormat::Sarif);
        let finding = make_finding(Severity::Error, "E001", "test error");
        let result = make_pipeline_result(vec![finding], None);
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        let region = &results[0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 10);
    }

    #[test]
    fn test_print_does_not_panic() {
        let reporter = Reporter::new(OutputFormat::Terminal);
        let result = make_pipeline_result(vec![], None);
        // print writes to stdout, just verify it doesn't panic
        reporter.print(&result).unwrap();
    }

    #[test]
    fn test_json_output_has_all_fields() {
        let reporter = Reporter::new(OutputFormat::Json);
        let finding = make_finding(Severity::Info, "I001", "info finding");
        let scores = QualityScores::new(100.0, 90.0, 80.0, 70.0, 60.0);
        let mut result = make_pipeline_result(vec![finding], Some(scores));
        result.total_findings = 1;
        let output = reporter.generate(&result).unwrap();
        let parsed: PipelineResult = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.total_findings, 1);
        assert_eq!(parsed.results.len(), 1);
        assert_eq!(parsed.results[0].findings.len(), 1);
        assert!(parsed.results[0].scores.is_some());
    }
}
