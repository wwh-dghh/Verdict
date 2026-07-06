//! Verdict — AI code, human confidence.
//!
//! A CLI tool for validating AI-generated code quality through
//! static analysis, security scanning, and AI-powered semantic review.

mod config;
mod git_diff;
mod lint;
mod models;
mod pipeline;
mod plugin;
mod report;
mod security;
mod semantic;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "verdict")]
#[command(about = "AI code, human confidence. Verify the quality of AI-generated code.")]
struct Cli {
    /// Target files or directories to analyze
    targets: Vec<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, short)]
    verbose: bool,

    #[arg(long)]
    version: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze code quality
    Check {
        /// Target files or directories
        targets: Vec<PathBuf>,
        /// Output format: terminal, json, sarif
        #[arg(long, short = 'f')]
        format: Option<String>,
        /// Enable AI semantic review (requires LLM API key in config)
        #[arg(long)]
        explain: bool,
        /// Enable git diff mode (only analyze changed files)
        #[arg(long)]
        diff: bool,
        /// Auto-fix suggestions (experimental)
        #[arg(long)]
        fix: bool,
    },
    /// Initialize a .verdict.yaml config file
    Init,
    /// Show available security rules
    Rules,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.version {
        println!("verdict 0.1.0");
        return Ok(());
    }

    // Logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("verdict=debug".parse()?),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    let config = config::ConfigLoader::load()?;

    match cli.command {
        Some(Commands::Init) => cmd_init(),
        Some(Commands::Rules) => cmd_rules(),
        Some(Commands::Check {
            targets,
            format,
            explain,
            diff,
            fix,
        }) => {
            let mut cfg = config;
            cfg.targets = if targets.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                targets
            };

            let overrides = config::CliOverrides {
                ai_review: explain,
                diff_mode: diff,
                fix,
                output_format: format.as_deref().map(parse_format),
                ..Default::default()
            };
            cfg = config::merge_config(cfg, overrides);

            cmd_check(&cfg).await
        }
        None => {
            // No subcommand — treat positional args as check targets
            let mut cfg = config;
            cfg.targets = if cli.targets.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                cli.targets
            };
            cmd_check(&cfg).await
        }
    }
}

async fn cmd_check(config: &models::Config) -> anyhow::Result<()> {
    tracing::info!("starting analysis of {} target(s)", config.targets.len());

    let mut builder = pipeline::PipelineBuilder::new();
    builder = builder.with_diff_mode(config.diff_mode);
    builder = builder.with_lint();
    if config.security_scan {
        builder = builder.with_security();
    }
    if config.ai_review {
        builder = builder.with_semantic(config.llm.clone());
    }

    let result = builder
        .build()
        .run(config.targets.clone(), config.ignore.clone())
        .await?;

    let reporter = report::Reporter::new(config.output);
    reporter.print(&result)?;

    let has_errors = result
        .results
        .iter()
        .flat_map(|r| &r.findings)
        .any(|f| f.severity == models::Severity::Error);

    if has_errors {
        println!("\n✗ Analysis failed — fix errors before committing.");
        std::process::exit(1);
    }

    println!("\n✓ Analysis passed.");
    Ok(())
}

fn cmd_init() -> anyhow::Result<()> {
    let template = r#"# Verdict — AI Code Verification Tool
# https://github.com/verdict-tool/verdict

# Targets to analyze (default: current directory)
# targets: ["./src"]

# Languages to include (empty = auto-detect)
# languages: [python, javascript, typescript]

# Enable AI semantic review (requires LLM API key)
# ai_review: true

# LLM configuration (optional)
# llm:
#   provider: "openai"
#   api_key: "${OPENAI_API_KEY}"
#   model: "gpt-4o-mini"
#   max_tokens: 500

# Output format: terminal, json, sarif
# output: terminal

# CI/CD thresholds (0-100)
# thresholds:
#   security: 70
#   code_quality: 60
#   overall: 50

# Enable git diff mode (only analyze changed files)
# diff_mode: false

# Patterns to ignore
ignore:
  - ".git"
  - "node_modules"
  - "__pycache__"
  - "target"
  - "venv"
"#;

    println!("{}", template.trim());
    println!("\nSave this as .verdict.yaml in your project root");

    // Also create plugins directory with example
    let plugins_dir = std::path::Path::new("plugins");
    if !plugins_dir.exists() {
        std::fs::create_dir_all(plugins_dir)?;
        let example = plugin::generate_template();
        std::fs::write(plugins_dir.join("example-rules.json"), &example)?;
        println!("\nCreated plugins/ directory with example-rules.json");
        println!("Edit or add .json files to plugins/ to define custom security rules");
    }

    Ok(())
}

fn cmd_rules() -> anyhow::Result<()> {
    println!("Available security rules:\n");
    for (code, name, desc) in RULES {
        println!("  {} — {} ({})", code, name, desc);
    }
    println!("\nLint rules are provided by the underlying linters (Ruff, Biome, etc.)");
    Ok(())
}

fn parse_format(s: &str) -> models::OutputFormat {
    match s {
        "json" => models::OutputFormat::Json,
        "sarif" => models::OutputFormat::Sarif,
        _ => models::OutputFormat::Terminal,
    }
}

const RULES: &[(&str, &str, &str)] = &[
    (
        "SEC001",
        "Potential SQL injection",
        "String concatenation in queries",
    ),
    ("SEC002", "Potential XSS", "innerHTML, document.write"),
    (
        "SEC003",
        "Hardcoded secrets",
        "API keys, passwords, tokens in source",
    ),
    ("SEC004", "Weak cryptography", "MD5, DES algorithms"),
    (
        "SEC005",
        "Debug logging leaks",
        "Print statements with sensitive data",
    ),
    ("SEC006", "Unsafe eval", "eval() usage"),
    (
        "SEC007",
        "Command injection",
        "String concat in subprocess/system calls",
    ),
];
