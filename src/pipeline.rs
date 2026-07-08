//! Pipeline orchestration — stages the analysis workflow.

use crate::models::*;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Instant;
use walkdir::WalkDir;

/// Trait for a pipeline stage that can be executed
#[async_trait::async_trait]
pub trait Stage: Send + Sync {
    fn name(&self) -> &str;
    async fn execute(&self, input: &[AnalysisResult]) -> Result<Vec<AnalysisResult>>;
}

/// Builder that assembles and runs the full pipeline
pub struct PipelineBuilder {
    stages: Vec<Box<dyn Stage>>,
    diff_mode: bool,
}

impl PipelineBuilder {
    pub fn new() -> Self {
        Self {
            stages: vec![],
            diff_mode: false,
        }
    }

    pub fn with_diff_mode(mut self, enabled: bool) -> Self {
        self.diff_mode = enabled;
        self
    }

    pub fn with_lint(mut self) -> Self {
        use crate::lint::LintStage;
        self.stages.push(Box::new(LintStage::new()));
        self
    }

    pub fn with_security(mut self) -> Self {
        use crate::security::SecurityStage;
        self.stages.push(Box::new(SecurityStage::new()));
        self
    }

    pub fn with_semantic(mut self, llm_config: Option<LLMConfig>) -> Self {
        use crate::semantic::SemanticStage;
        self.stages.push(Box::new(SemanticStage::new(llm_config)));
        self
    }

    pub fn build(self) -> Pipeline {
        Pipeline {
            stages: self.stages,
            diff_mode: self.diff_mode,
        }
    }
}

/// The analysis pipeline — runs stages sequentially
pub struct Pipeline {
    stages: Vec<Box<dyn Stage>>,
    diff_mode: bool,
}

impl Pipeline {
    /// Run all stages on the given file paths
    pub async fn run(
        &self,
        targets: Vec<PathBuf>,
        ignore_patterns: Vec<String>,
    ) -> Result<PipelineResult> {
        let start = Instant::now();
        let mut stages_completed = Vec::new();

        // Preprocess stage — discover target files
        let preprocess = PreprocessStage::new(targets, ignore_patterns, self.diff_mode);
        let preprocess_start = Instant::now();
        let mut results: Vec<AnalysisResult> = preprocess
            .execute(&[])
            .await
            .context("preprocess stage failed")?;
        stages_completed.push(PipelineStage::Preprocess);
        let preprocess_duration = preprocess_start.elapsed().as_millis() as u64;
        results.iter_mut().for_each(|r| {
            r.duration_ms += preprocess_duration;
        });

        // Run each configured stage in sequence
        for stage in &self.stages {
            let stage_start = Instant::now();
            let input = std::mem::take(&mut results);
            results = stage
                .execute(&input)
                .await
                .with_context(|| format!("stage '{}' failed", stage.name()))?;
            let elapsed = stage_start.elapsed();
            tracing::info!("stage '{}' completed in {:?}", stage.name(), elapsed);

            // Add duration to each result
            let ms = elapsed.as_millis() as u64;
            results.iter_mut().for_each(|r| r.duration_ms += ms);

            // Track the completed stage by name
            match stage.name() {
                "lint" => stages_completed.push(PipelineStage::Lint),
                "security" => stages_completed.push(PipelineStage::Security),
                "semantic" => stages_completed.push(PipelineStage::Semantic),
                _ => {}
            }
        }

        // Aggregate stage — compute scores
        let aggregate = AggregateStage {};
        results = aggregate
            .execute(&results)
            .await
            .context("aggregate stage failed")?;
        stages_completed.push(PipelineStage::Aggregate);

        let duration = start.elapsed();
        let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();

        // Check thresholds against the lowest-scoring file
        let failed_thresholds: Vec<String> = if let Some(lowest) = results.iter().min_by_key(|r| {
            r.scores
                .as_ref()
                .map(|s| s.overall as u32)
                .unwrap_or(u32::MAX)
        }) {
            if let Some(scores) = lowest.scores.as_ref() {
                let mut failures = Vec::new();
                // We don't have access to config.thresholds here, so we log
                // threshold info for now — actual gating is done in main.rs
                if scores.security < 50.0 {
                    failures.push(format!(
                        "security score {:.0} below critical threshold",
                        scores.security
                    ));
                }
                failures
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        tracing::info!(
            "pipeline completed in {:?}: {} files, {} findings",
            duration,
            results.len(),
            total_findings
        );

        Ok(PipelineResult {
            stages_completed,
            results,
            total_findings,
            failed_thresholds,
            exit_code: 0,
        })
    }
}

// ─── Preprocess Stage ────────────────────────────────────────────────

struct PreprocessStage {
    targets: Vec<PathBuf>,
    ignore_patterns: Vec<String>,
    diff_mode: bool,
}

impl PreprocessStage {
    fn new(targets: Vec<PathBuf>, ignore_patterns: Vec<String>, diff_mode: bool) -> Self {
        Self {
            targets,
            ignore_patterns,
            diff_mode,
        }
    }
}

#[async_trait::async_trait]
impl Stage for PreprocessStage {
    fn name(&self) -> &str {
        "preprocess"
    }

    async fn execute(&self, _input: &[AnalysisResult]) -> Result<Vec<AnalysisResult>> {
        let mut results = Vec::new();
        let ignore_set: std::collections::HashSet<&str> =
            self.ignore_patterns.iter().map(|s| s.as_str()).collect();

        // In diff mode, only analyze files changed in git
        if self.diff_mode {
            let mut changed_files = Vec::new();
            let mut git_failed = false;

            for target in &self.targets {
                let root = if target.is_dir() {
                    crate::git_diff::find_repo_root(target).unwrap_or_else(|_| target.clone())
                } else {
                    target.parent().unwrap_or(target).to_path_buf()
                };

                if crate::git_diff::is_git_repo(&root) {
                    let opts = crate::git_diff::DiffOptions::default();
                    match crate::git_diff::discover_changed_files(&root, &opts) {
                        Ok(files) => {
                            for f in files {
                                let full_path = if f.is_relative() { root.join(&f) } else { f };
                                if full_path.exists() && !changed_files.contains(&full_path) {
                                    changed_files.push(full_path);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("git diff failed for {}: {}", root.display(), e);
                            git_failed = true;
                        }
                    }
                } else {
                    // Not a git repo — fall back to full scan
                    git_failed = true;
                }
            }

            // If git diff failed, fall back to full scan for targets that are files/dirs
            if git_failed && changed_files.is_empty() {
                tracing::warn!("git diff failed or no git repo found, falling back to full scan");
                // Continue to full scan path below
            } else if !changed_files.is_empty() {
                for path in changed_files {
                    if let Some(lang) = Language::from_path(&path) {
                        results.push(AnalysisResult {
                            path,
                            language: Some(lang),
                            findings: Vec::new(),
                            scores: None,
                            duration_ms: 0,
                        });
                    }
                }

                tracing::info!(
                    "preprocess (diff mode): found {} changed files",
                    results.len()
                );
                return Ok(results);
            }
            // Fall through to full scan below if git diff failed and no files found
        }

        // Full scan mode
        for target in &self.targets {
            if target.is_file() {
                // Single file target
                if let Some(lang) = Language::from_path(target) {
                    results.push(AnalysisResult {
                        path: target.clone(),
                        language: Some(lang),
                        findings: Vec::new(),
                        scores: None,
                        duration_ms: 0,
                    });
                }
            } else if target.is_dir() {
                // Walk directory, collecting supported files
                for entry in WalkDir::new(target)
                    .min_depth(1)
                    .follow_links(false)
                    .into_iter()
                    .filter_entry(|e| {
                        let name = e.file_name().to_string_lossy();
                        !ignore_set.contains(name.as_ref())
                    })
                    .filter_map(|e| e.ok())
                {
                    if entry.file_type().is_file() {
                        let path = entry.path().to_path_buf();
                        if let Some(lang) = Language::from_path(&path) {
                            results.push(AnalysisResult {
                                path,
                                language: Some(lang),
                                findings: Vec::new(),
                                scores: None,
                                duration_ms: 0,
                            });
                        }
                    }
                }
            }
        }

        tracing::info!("preprocess: discovered {} files", results.len());
        Ok(results)
    }
}

// ─── Aggregate Stage ─────────────────────────────────────────────────

struct AggregateStage;

#[async_trait::async_trait]
impl Stage for AggregateStage {
    fn name(&self) -> &str {
        "aggregate"
    }

    async fn execute(&self, input: &[AnalysisResult]) -> Result<Vec<AnalysisResult>> {
        let mut results = Vec::new();

        for r in input {
            let errors = r
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Error)
                .count() as f64;
            let warnings = r
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Warning)
                .count() as f64;
            let total = r.findings.len() as f64;

            let code_quality = if total > 0.0 {
                (1.0 - (errors * 10.0 + warnings * 3.0) / (total * 10.0 + 1.0)) * 100.0
            } else {
                100.0
            };
            let code_quality = code_quality.clamp(0.0, 100.0);

            // Security score: penalize based on number and severity of findings
            let sec_findings: Vec<_> = r
                .findings
                .iter()
                .filter(|f| matches!(f.category, Category::Security))
                .collect();

            let security = if sec_findings.is_empty() {
                100.0
            } else {
                let penalty = sec_findings
                    .iter()
                    .map(|f| match f.severity {
                        Severity::Error => 15.0,
                        Severity::Warning => 5.0,
                        Severity::Info => 2.0,
                    })
                    .sum::<f64>();
                (100.0 - penalty).clamp(0.0, 100.0)
            };

            let scores = QualityScores::new(
                security,
                code_quality,
                80.0, // placeholder — perf needs deeper analysis
                60.0, // placeholder — testing needs test runner integration
                75.0, // placeholder — AI risk needs LLM review
            );

            results.push(AnalysisResult {
                path: r.path.clone(),
                language: r.language,
                findings: r.findings.clone(),
                scores: Some(scores),
                duration_ms: r.duration_ms,
            });
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn make_result(path: &str, findings: Vec<Finding>) -> AnalysisResult {
        AnalysisResult {
            path: PathBuf::from(path),
            language: Language::from_path(Path::new(path)),
            findings,
            scores: None,
            duration_ms: 0,
        }
    }

    #[tokio::test]
    async fn test_preprocess_stage_single_file() {
        let stage = PreprocessStage::new(
            vec![PathBuf::from("src/main.rs")],
            vec![".git".into()],
            false,
        );
        let results = stage.execute(&[]).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, PathBuf::from("src/main.rs"));
        assert_eq!(results[0].language, Some(Language::Rust));
    }

    #[tokio::test]
    async fn test_preprocess_stage_unknown_extension() {
        let stage = PreprocessStage::new(vec![PathBuf::from("readme.txt")], vec![], false);
        let results = stage.execute(&[]).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_preprocess_stage_walks_directory() {
        // Use the repo's own src/ directory which is known to contain .rs files
        let stage = PreprocessStage::new(vec![PathBuf::from("src")], vec!["target".into()], false);
        let results = stage.execute(&[]).await.unwrap();
        // Should find at least main.rs and models.rs
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.language == Some(Language::Rust)));
    }

    #[tokio::test]
    async fn test_preprocess_stage_respects_ignore() {
        let stage = PreprocessStage::new(vec![PathBuf::from(".")], vec!["src".into()], false);
        let results = stage.execute(&[]).await.unwrap();
        // With "src" in the ignore list, walking "." should skip it
        assert!(results.is_empty() || !results.iter().any(|r| r.path.starts_with("src")));
    }

    #[tokio::test]
    async fn test_aggregate_stage_empty_input() {
        let stage = AggregateStage;
        let result = stage.execute(&[]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_aggregate_stage_no_findings_full_score() {
        let stage = AggregateStage;
        let input = vec![make_result("src/lib.rs", vec![])];
        let result = stage.execute(&input).await.unwrap();
        assert_eq!(result.len(), 1);
        let scores = result[0].scores.as_ref().unwrap();
        assert_eq!(scores.security, 100.0);
        assert_eq!(scores.code_quality, 100.0);
    }

    #[tokio::test]
    async fn test_aggregate_stage_security_finding_drops_score() {
        let stage = AggregateStage;
        let finding = Finding::new(
            Category::Security,
            Severity::Error,
            "SEC001",
            "SQL injection",
            PathBuf::from("src/lib.rs"),
            Some(1),
        );
        let input = vec![make_result("src/lib.rs", vec![finding])];
        let result = stage.execute(&input).await.unwrap();
        let scores = result[0].scores.as_ref().unwrap();
        // 1 error security finding -> 100 - 15 = 85
        assert_eq!(scores.security, 85.0);
        // Errors pull code_quality down
        assert!(scores.code_quality < 100.0);
    }

    #[tokio::test]
    async fn test_aggregate_stage_multiple_security_findings_drop_more() {
        let stage = AggregateStage;
        let findings = vec![
            Finding::new(
                Category::Security,
                Severity::Error,
                "SEC001",
                "SQL injection",
                PathBuf::from("src/lib.rs"),
                Some(1),
            ),
            Finding::new(
                Category::Security,
                Severity::Error,
                "SEC003",
                "Hardcoded secret",
                PathBuf::from("src/lib.rs"),
                Some(5),
            ),
            Finding::new(
                Category::Security,
                Severity::Warning,
                "SEC004",
                "Weak crypto",
                PathBuf::from("src/lib.rs"),
                Some(10),
            ),
        ];
        let input = vec![make_result("src/lib.rs", findings)];
        let result = stage.execute(&input).await.unwrap();
        let scores = result[0].scores.as_ref().unwrap();
        // 2 errors (15*2=30) + 1 warning (5) = 35 penalty -> 100 - 35 = 65
        assert_eq!(scores.security, 65.0);
    }

    #[tokio::test]
    async fn test_aggregate_stage_warnings_penalize_quality() {
        let stage = AggregateStage;
        let warnings: Vec<Finding> = (0..3)
            .map(|i| {
                Finding::new(
                    Category::Lint,
                    Severity::Warning,
                    "W001",
                    format!("warn {i}"),
                    PathBuf::from("src/lib.rs"),
                    Some(i + 1),
                )
            })
            .collect();
        let input = vec![make_result("src/lib.rs", warnings)];
        let result = stage.execute(&input).await.unwrap();
        let scores = result[0].scores.as_ref().unwrap();
        // No security findings -> security stays 100
        assert_eq!(scores.security, 100.0);
        // Warnings should reduce code_quality below 100
        assert!(scores.code_quality < 100.0);
    }

    #[tokio::test]
    async fn test_pipeline_builder_constructs() {
        let builder = PipelineBuilder::new();
        assert!(!builder.diff_mode);
        let pipeline = builder.build();
        // No stages means just preprocess + aggregate
        let result = pipeline
            .run(vec![PathBuf::from("readme.txt")], vec![])
            .await
            .unwrap();
        // txt file isn't a supported language, so no files discovered
        assert_eq!(result.results.len(), 0);
        // Both stages should be tracked
        assert!(result.stages_completed.contains(&PipelineStage::Preprocess));
        assert!(result.stages_completed.contains(&PipelineStage::Aggregate));
    }

    #[tokio::test]
    async fn test_pipeline_records_all_stages() {
        let pipeline = PipelineBuilder::new().with_lint().with_security().build();
        let result = pipeline
            .run(vec![PathBuf::from("src")], vec!["target".into()])
            .await
            .unwrap();

        let stages = &result.stages_completed;
        assert!(stages.contains(&PipelineStage::Preprocess));
        assert!(stages.contains(&PipelineStage::Lint));
        assert!(stages.contains(&PipelineStage::Security));
        assert!(stages.contains(&PipelineStage::Aggregate));
    }
}
