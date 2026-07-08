//! Core data types and models for the Verdict AI code verification tool.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Programming language support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Go,
    Rust,
}

impl Language {
    /// Detect language from file extension
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        match ext {
            "py" => Some(Language::Python),
            "js" | "jsx" => Some(Language::JavaScript),
            "ts" | "tsx" => Some(Language::TypeScript),
            "go" => Some(Language::Go),
            "rs" => Some(Language::Rust),
            _ => None,
        }
    }

    /// Human-readable display name for the language
    #[allow(dead_code)] // public API used by external tools and future features
    pub fn display_name(&self) -> &'static str {
        match self {
            Language::Python => "Python",
            Language::JavaScript => "JavaScript",
            Language::TypeScript => "TypeScript",
            Language::Go => "Go",
            Language::Rust => "Rust",
        }
    }

    /// Default linter for this language
    #[allow(dead_code)] // public API used by external tools and future features
    pub fn default_linter(&self) -> LinterKind {
        match self {
            Language::Python => LinterKind::Ruff,
            Language::JavaScript | Language::TypeScript => LinterKind::Biome,
            Language::Go => LinterKind::GolangCiLint,
            Language::Rust => LinterKind::Clippy,
        }
    }

    /// File extensions for this language
    #[allow(dead_code)] // public API used by external tools and future features
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            Language::Python => &["py"],
            Language::JavaScript => &["js", "jsx"],
            Language::TypeScript => &["ts", "tsx"],
            Language::Go => &["go"],
            Language::Rust => &["rs"],
        }
    }
}

/// Built-in linter backends
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinterKind {
    Ruff,
    Biome,
    Oxlint,
    GolangCiLint,
    Clippy,
}

/// Severity of a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    /// Human-readable display name for the severity level
    #[allow(dead_code)] // public API used by external tools and future features
    pub fn display_name(&self) -> &'static str {
        match self {
            Severity::Error => "Error",
            Severity::Warning => "Warning",
            Severity::Info => "Info",
        }
    }
}

/// Category of a finding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Code style and quality issues
    Lint,
    /// Security vulnerabilities
    Security,
    /// Performance concerns
    Performance,
    /// Test coverage gaps
    Testing,
    /// AI-specific code quality issues
    AiSemantic,
    /// Architecture / best practice violations
    BestPractice,
}

/// A single finding discovered during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Category of the finding (lint, security, etc.)
    pub category: Category,
    /// Severity level
    pub severity: Severity,
    /// Rule code identifier (e.g., "SEC001")
    pub code: String,
    /// Human-readable description of the issue
    pub message: String,
    /// Path to the source file
    pub file: PathBuf,
    /// Line number where the issue starts
    pub line: Option<usize>,
    /// Column number where the issue starts
    pub column: Option<usize>,
    /// Suggested fix for the issue
    pub suggestion: Option<String>,
    /// AI-generated explanation (when LLM-as-Judge is enabled)
    pub ai_explanation: Option<String>,
}

impl Finding {
    /// Create a new finding with basic fields
    pub fn new(
        category: Category,
        severity: Severity,
        code: impl Into<String>,
        message: impl Into<String>,
        file: PathBuf,
        line: Option<usize>,
    ) -> Self {
        Self {
            category,
            severity,
            code: code.into(),
            message: message.into(),
            file,
            line,
            column: None,
            suggestion: None,
            ai_explanation: None,
        }
    }

    /// Returns true if this finding is a security vulnerability
    #[allow(dead_code)] // public API for external consumers
    pub fn is_security(&self) -> bool {
        matches!(self.category, Category::Security)
    }

    /// Returns true if this finding has error severity
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// Multi-dimensional quality scores for analyzed code
///
/// All scores are on a 0-100 scale, with 100 being the best.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityScores {
    /// Security vulnerability score
    pub security: f64,
    /// Code style and quality score
    pub code_quality: f64,
    /// Performance optimization score
    pub performance: f64,
    /// Test coverage score
    pub test_coverage: f64,
    /// AI-generated code risk score
    pub ai_risk: f64,
    /// Weighted overall score
    pub overall: f64,
}

impl QualityScores {
    /// Create a new quality scores instance with computed weighted overall
    pub fn new(
        security: f64,
        code_quality: f64,
        performance: f64,
        test_coverage: f64,
        ai_risk: f64,
    ) -> Self {
        let weights = [0.35, 0.25, 0.20, 0.10, 0.10];
        let scores = [security, code_quality, performance, test_coverage, ai_risk];
        let overall: f64 = weights.iter().zip(scores.iter()).map(|(w, s)| w * s).sum();
        Self {
            security,
            code_quality,
            performance,
            test_coverage,
            ai_risk,
            overall,
        }
    }
}

/// Analysis result for a single file or directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub path: PathBuf,
    pub language: Option<Language>,
    pub findings: Vec<Finding>,
    pub scores: Option<QualityScores>,
    pub duration_ms: u64,
}

/// Output format for reports
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Terminal,
    Json,
    Sarif,
}

/// Configuration thresholds for CI/CD gating
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    #[serde(default = "default_security_threshold")]
    pub security: f64,
    #[serde(default = "default_quality_threshold")]
    pub code_quality: f64,
    #[serde(default = "default_overall_threshold")]
    pub overall: f64,
}

impl Thresholds {
    /// Check if any threshold differs from the default values
    pub fn is_default(&self) -> bool {
        (self.security - 70.0).abs() < f64::EPSILON
            && (self.code_quality - 60.0).abs() < f64::EPSILON
            && (self.overall - 50.0).abs() < f64::EPSILON
    }
}

fn default_security_threshold() -> f64 {
    70.0
}
fn default_quality_threshold() -> f64 {
    60.0
}
fn default_overall_threshold() -> f64 {
    50.0
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            security: 70.0,
            code_quality: 60.0,
            overall: 50.0,
        }
    }
}

/// Main configuration for a verdict run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Directories or files to analyze
    pub targets: Vec<PathBuf>,
    /// Languages to include (empty = auto-detect)
    #[serde(default)]
    pub languages: Vec<Language>,
    /// Which linters to enable
    #[serde(default)]
    pub linters: Vec<LinterKind>,
    /// Whether to run security scanning
    #[serde(default = "default_true")]
    pub security_scan: bool,
    /// Whether to run AI semantic review
    #[serde(default)]
    pub ai_review: bool,
    /// LLM provider configuration
    pub llm: Option<LLMConfig>,
    /// Output format
    #[serde(default)]
    pub output: OutputFormat,
    /// CI/CD thresholds
    #[serde(default)]
    pub thresholds: Thresholds,
    /// Whether to use git diff mode
    #[serde(default)]
    pub diff_mode: bool,
    /// Patterns to ignore
    #[serde(default)]
    pub ignore: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    pub provider: String,
    pub api_key: String,
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: usize,
    #[serde(default = "default_max_input_chars")]
    pub max_input_chars: usize,
}

fn default_true() -> bool {
    true
}
fn default_max_tokens() -> usize {
    500
}
fn default_max_input_chars() -> usize {
    4000
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: vec![],
            languages: vec![],
            linters: vec![],
            security_scan: true,
            ai_review: false,
            llm: None,
            output: OutputFormat::default(),
            thresholds: Thresholds::default(),
            diff_mode: false,
            ignore: vec![
                ".git".into(),
                "node_modules".into(),
                "__pycache__".into(),
                "target".into(),
                "venv".into(),
            ],
        }
    }
}

/// Analysis pipeline stage
#[allow(dead_code)] // All variants are part of the public API for result reporting
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PipelineStage {
    Preprocess,
    Lint,
    Security,
    Semantic,
    Aggregate,
    Report,
}

/// Overall pipeline execution result
#[derive(Debug, Clone, Serialize)]
pub struct PipelineResult {
    pub stages_completed: Vec<PipelineStage>,
    pub results: Vec<AnalysisResult>,
    pub total_findings: usize,
    pub failed_thresholds: Vec<String>,
    pub exit_code: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_finding_creation() {
        let finding = Finding::new(
            Category::Security,
            Severity::Error,
            "SEC001",
            "SQL injection detected",
            PathBuf::from("test.py"),
            Some(10),
        );
        assert_eq!(finding.code, "SEC001");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(finding.line, Some(10));
        assert!(finding.suggestion.is_none());
    }

    #[test]
    fn test_quality_scores_weighted_average() {
        let scores = QualityScores::new(100.0, 80.0, 60.0, 40.0, 20.0);
        // 0.35*100 + 0.25*80 + 0.20*60 + 0.10*40 + 0.10*20 = 35 + 20 + 12 + 4 + 2 = 73
        assert!((scores.overall - 73.0).abs() < 0.01);
    }

    #[test]
    fn test_quality_scores_perfect() {
        let scores = QualityScores::new(100.0, 100.0, 100.0, 100.0, 100.0);
        assert!((scores.overall - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_quality_scores_worst() {
        let scores = QualityScores::new(0.0, 0.0, 0.0, 0.0, 0.0);
        assert!((scores.overall - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_language_detection_python() {
        assert_eq!(
            Language::from_path(&PathBuf::from("main.py")),
            Some(Language::Python)
        );
    }

    #[test]
    fn test_language_detection_js() {
        assert_eq!(
            Language::from_path(&PathBuf::from("app.js")),
            Some(Language::JavaScript)
        );
    }

    #[test]
    fn test_language_detection_ts() {
        assert_eq!(
            Language::from_path(&PathBuf::from("app.ts")),
            Some(Language::TypeScript)
        );
    }

    #[test]
    fn test_language_detection_go() {
        assert_eq!(
            Language::from_path(&PathBuf::from("main.go")),
            Some(Language::Go)
        );
    }

    #[test]
    fn test_language_detection_rust() {
        assert_eq!(
            Language::from_path(&PathBuf::from("main.rs")),
            Some(Language::Rust)
        );
    }

    #[test]
    fn test_language_detection_unknown() {
        assert_eq!(Language::from_path(&PathBuf::from("readme.txt")), None);
    }

    #[test]
    fn test_output_format_default() {
        let format: OutputFormat = Default::default();
        assert_eq!(format, OutputFormat::Terminal);
    }

    #[test]
    fn test_thresholds_default() {
        let thresholds = Thresholds::default();
        assert_eq!(thresholds.security, 70.0);
        assert_eq!(thresholds.code_quality, 60.0);
        assert_eq!(thresholds.overall, 50.0);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Error < Severity::Warning);
        assert!(Severity::Warning < Severity::Info);
    }

    #[test]
    fn test_config_default_targets_empty() {
        let config = Config::default();
        assert!(config.targets.is_empty());
    }

    #[test]
    fn test_config_default_ignore_patterns() {
        let config = Config::default();
        assert!(config.ignore.contains(&".git".to_string()));
        assert!(config.ignore.contains(&"node_modules".to_string()));
    }

    #[test]
    fn test_language_display_name() {
        assert_eq!(Language::Python.display_name(), "Python");
        assert_eq!(Language::JavaScript.display_name(), "JavaScript");
        assert_eq!(Language::TypeScript.display_name(), "TypeScript");
        assert_eq!(Language::Go.display_name(), "Go");
        assert_eq!(Language::Rust.display_name(), "Rust");
    }

    #[test]
    fn test_severity_display_name() {
        assert_eq!(Severity::Error.display_name(), "Error");
        assert_eq!(Severity::Warning.display_name(), "Warning");
        assert_eq!(Severity::Info.display_name(), "Info");
    }

    #[test]
    fn test_finding_is_security() {
        let sec_finding = Finding::new(
            Category::Security,
            Severity::Error,
            "SEC001",
            "SQL injection",
            PathBuf::from("test.py"),
            Some(1),
        );
        assert!(sec_finding.is_security());

        let lint_finding = Finding::new(
            Category::Lint,
            Severity::Warning,
            "W001",
            "unused var",
            PathBuf::from("test.rs"),
            Some(5),
        );
        assert!(!lint_finding.is_security());
    }

    #[test]
    fn test_finding_is_error() {
        let error_finding = Finding::new(
            Category::Security,
            Severity::Error,
            "SEC001",
            "SQL injection",
            PathBuf::from("test.py"),
            Some(1),
        );
        assert!(error_finding.is_error());

        let warning_finding = Finding::new(
            Category::Lint,
            Severity::Warning,
            "W001",
            "unused var",
            PathBuf::from("test.rs"),
            Some(5),
        );
        assert!(!warning_finding.is_error());
    }
}
