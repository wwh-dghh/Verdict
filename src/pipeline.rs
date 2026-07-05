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
}

impl PipelineBuilder {
    pub fn new() -> Self {
        Self { stages: vec![] }
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
        }
    }
}

/// The analysis pipeline — runs stages sequentially
pub struct Pipeline {
    stages: Vec<Box<dyn Stage>>,
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
        let preprocess = PreprocessStage::new(targets, ignore_patterns);
        let mut results: Vec<AnalysisResult> = preprocess
            .execute(&[])
            .await
            .context("preprocess stage failed")?;

        // Run each stage in sequence
        for stage in &self.stages {
            let stage_start = Instant::now();
            let input = std::mem::take(&mut results);
            results = stage
                .execute(&input)
                .await
                .with_context(|| format!("stage '{}' failed", stage.name()))?;
            let elapsed = stage_start.elapsed();
            tracing::info!("stage '{}' completed in {:?}", stage.name(), elapsed);
        }

        // Stage: Aggregate scores
        let aggregate = AggregateStage {};
        results = aggregate
            .execute(&results)
            .await
            .context("aggregate stage failed")?;
        stages_completed.push(PipelineStage::Aggregate);

        let duration = start.elapsed();
        let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();

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
            failed_thresholds: vec![],
            exit_code: 0,
        })
    }
}

// ─── Preprocess Stage ────────────────────────────────────────────────

struct PreprocessStage {
    targets: Vec<PathBuf>,
    ignore_patterns: Vec<String>,
}

impl PreprocessStage {
    fn new(targets: Vec<PathBuf>, ignore_patterns: Vec<String>) -> Self {
        Self {
            targets,
            ignore_patterns,
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

            // Security defaults to 100 if no security findings
            let security = if r
                .findings
                .iter()
                .any(|f| matches!(f.category, Category::Security))
            {
                50.0
            } else {
                100.0
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
