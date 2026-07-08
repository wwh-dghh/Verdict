//! Verdict — AI code, human confidence.
//!
//! A CLI tool for validating AI-generated code quality through
//! static analysis, security scanning, and AI-powered semantic review.

mod config;
mod git_diff;
mod lint;
mod marketplace;
mod models;
mod pipeline;
mod plugin;
mod report;
mod security;
mod semantic;
mod wasm_plugin;

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "verdict")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "AI code, human confidence. Verify the quality of AI-generated code.")]
struct Cli {
    /// Target files or directories to analyze
    targets: Vec<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, short)]
    verbose: bool,
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
    /// List loaded plugins (JSON and WASM)
    Plugins,
    /// Set up git pre-commit hook
    Hooks {
        /// Remove the hook
        #[arg(long)]
        uninstall: bool,
    },
    /// Manage plugins from the Verdict marketplace
    Plugin {
        #[command(subcommand)]
        command: PluginCommands,
    },
}

#[derive(Subcommand, Debug)]
enum PluginCommands {
    /// List available plugins in the marketplace
    List {
        /// Search query (optional)
        #[arg(long)]
        search: Option<String>,
    },
    /// Install a plugin from the marketplace
    Install {
        /// Plugin ID to install
        plugin_id: String,
    },
    /// Uninstall an installed plugin
    Uninstall {
        /// Plugin ID to uninstall
        plugin_id: String,
    },
    /// List installed plugins
    ListInstalled,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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
        Some(Commands::Plugins) => cmd_plugins(),
        Some(Commands::Hooks { uninstall }) => cmd_hooks(uninstall),
        Some(Commands::Plugin { command }) => cmd_plugin(command),
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
        .any(|f| f.is_error());

    if has_errors {
        anyhow::bail!("Analysis failed — fix errors before committing.");
    }

    // Check quality thresholds
    let mut threshold_failures = Vec::new();
    for r in &result.results {
        if let Some(scores) = &r.scores {
            if scores.security < config.thresholds.security {
                threshold_failures.push(format!(
                    "{}: security {:.0} < threshold {:.0}",
                    r.path.display(),
                    scores.security,
                    config.thresholds.security
                ));
            }
            if scores.code_quality < config.thresholds.code_quality {
                threshold_failures.push(format!(
                    "{}: code_quality {:.0} < threshold {:.0}",
                    r.path.display(),
                    scores.code_quality,
                    config.thresholds.code_quality
                ));
            }
            if scores.overall < config.thresholds.overall {
                threshold_failures.push(format!(
                    "{}: overall {:.0} < threshold {:.0}",
                    r.path.display(),
                    scores.overall,
                    config.thresholds.overall
                ));
            }
        }
    }

    if !threshold_failures.is_empty() {
        anyhow::bail!(
            "Analysis failed — threshold violations:\n{}",
            threshold_failures.join("\n")
        );
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

    let config_path = PathBuf::from(".verdict.yaml");
    if config_path.exists() {
        println!("⚠ .verdict.yaml already exists, skipping");
    } else {
        fs::write(&config_path, template.trim())?;
        println!("✓ Created .verdict.yaml");
    }

    // Also create plugins directory with example
    let plugins_dir = std::path::Path::new("plugins");
    if !plugins_dir.exists() {
        std::fs::create_dir_all(plugins_dir)?;
        let example = plugin::generate_template();
        std::fs::write(plugins_dir.join("example-rules.json"), &example)?;
        println!("✓ Created plugins/ directory with example-rules.json");
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
    println!("\nCustom rules: place .json files in ~/.verdict/plugins/ or ./plugins/");
    println!("Run 'verdict hooks' to set up git pre-commit hook");
    Ok(())
}

fn cmd_plugins() -> anyhow::Result<()> {
    println!("Loaded plugins:\n");

    // JSON plugins
    let json_loader = plugin::PluginLoader::new();
    let json_plugins = match json_loader.load_all() {
        Ok(plugins) => plugins,
        Err(e) => {
            tracing::warn!("failed to load JSON plugins: {}", e);
            vec![]
        }
    };
    if json_plugins.is_empty() {
        println!("  (no JSON plugins found)");
    } else {
        println!("  JSON rule plugins:");
        for p in &json_plugins {
            println!(
                "    - {} v{} ({} rule{})",
                p.name,
                p.version,
                p.rules.len(),
                if p.rules.len() == 1 { "" } else { "s" }
            );
            if !p.description.is_empty() {
                println!("        {}", p.description);
            }
        }
    }

    // WASM plugins
    println!();
    let wasm_loader = wasm_plugin::WasmPluginLoader::new();
    let wasm_plugins = match wasm_loader.load_all() {
        Ok(plugins) => plugins,
        Err(e) => {
            tracing::warn!("failed to load WASM plugins: {}", e);
            vec![]
        }
    };
    if wasm_plugins.is_empty() {
        println!("  (no WASM plugins found)");
    } else {
        println!("  WASM plugins:");
        for p in &wasm_plugins {
            println!("    - {} v{}", p.name(), p.version());
        }
    }

    println!("\nPlugin directories:");
    for dir in json_loader.plugin_dirs() {
        println!("  - {}", dir.display());
    }
    for dir in wasm_loader.plugin_dirs() {
        println!("  - {} (wasm)", dir.display());
    }

    println!("\nTo install a plugin, drop a .json (rules) or .wasm file into one of the directories above.");
    Ok(())
}

fn cmd_hooks(uninstall: bool) -> anyhow::Result<()> {
    // Find git hooks directory
    let hooks_dir = find_git_hooks_dir()?;

    if uninstall {
        let hook_path = hooks_dir.join("pre-commit");
        if hook_path.exists() {
            let content = fs::read_to_string(&hook_path)?;
            if content.contains("# verdict-precommit") {
                fs::remove_file(&hook_path)?;
                println!("✓ Removed verdict pre-commit hook");
            } else {
                println!("⚠ Pre-commit hook exists but was not created by verdict");
                println!("  Remove manually: {}", hook_path.display());
            }
        } else {
            println!("No pre-commit hook found");
        }
        return Ok(());
    }

    // Install hook
    let hook_path = hooks_dir.join("pre-commit");
    if hook_path.exists() {
        let content = fs::read_to_string(&hook_path)?;
        if content.contains("# verdict-precommit") {
            fs::write(&hook_path, generate_hook_script())?;
            println!("✓ Updated verdict pre-commit hook");
            return Ok(());
        }
        anyhow::bail!(
            "Pre-commit hook already exists at {}\n\
             Remove it first or use --uninstall if it was created by verdict",
            hook_path.display()
        );
    }

    // Create hooks directory if it doesn't exist
    fs::create_dir_all(&hooks_dir)?;

    fs::write(&hook_path, generate_hook_script())?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    println!(
        "✓ Installed verdict pre-commit hook at {}",
        hook_path.display()
    );
    println!("  Runs 'verdict check --diff' before each commit");
    println!("  To skip: git commit --no-verify");
    Ok(())
}

fn find_git_hooks_dir() -> anyhow::Result<PathBuf> {
    let output = tokio::task::block_in_place(|| {
        std::process::Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
    })?;

    if !output.status.success() {
        anyhow::bail!("not a git repository");
    }

    let root = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(PathBuf::from(root).join(".git").join("hooks"))
}

fn generate_hook_script() -> String {
    if cfg!(target_os = "windows") {
        r"@echo off
REM verdict-precommit
verdict check --diff --format terminal
if %errorlevel% neq 0 (
    echo.
    echo Verdict found issues. Fix them before committing.
    echo To skip: git commit --no-verify
    exit /b 1
)
"
        .to_string()
    } else {
        r#"#!/bin/sh
# verdict-precommit
verdict check --diff --format terminal
if [ $? -ne 0 ]; then
    echo ""
    echo "Verdict found issues. Fix them before committing."
    echo "To skip: git commit --no-verify"
    exit 1
fi
"#
        .to_string()
    }
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

/// Handle plugin marketplace commands
fn cmd_plugin(command: PluginCommands) -> anyhow::Result<()> {
    let plugin_dir = get_plugin_dir()?;
    let client = marketplace::MarketplaceClient::new(
        "https://marketplace.verdict.dev".to_string(),
        plugin_dir,
    );

    match command {
        PluginCommands::List { search } => cmd_plugin_list(&client, search.as_deref()),
        PluginCommands::Install { plugin_id } => cmd_plugin_install(&client, &plugin_id),
        PluginCommands::Uninstall { plugin_id } => cmd_plugin_uninstall(&client, &plugin_id),
        PluginCommands::ListInstalled => cmd_plugin_list_installed(&client),
    }
}

fn cmd_plugin_list(
    client: &marketplace::MarketplaceClient,
    search: Option<&str>,
) -> anyhow::Result<()> {
    println!("Verdict Plugin Marketplace\n");
    println!("Searching for plugins...");

    let plugins = if let Some(q) = search {
        client.search_plugins(q)?
    } else {
        client.list_plugins()?
    };

    if plugins.is_empty() {
        println!("\nNo plugins found. The marketplace is coming soon!");
        println!("In the meantime, create custom rules by placing .json files in:");
        println!("  ~/.verdict/plugins/  (user-level)");
        println!("  ./plugins/           (project-level)");
        println!("\nRun 'verdict init' to generate an example plugin file.");
    } else {
        println!("\n{:<20} {:<10} {:<30}", "ID", "Version", "Description");
        println!("{}", "─".repeat(60));
        for p in &plugins {
            println!("{:<20} {:<10} {:<30}", p.id, p.version, p.description);
        }
    }

    Ok(())
}

fn cmd_plugin_install(
    client: &marketplace::MarketplaceClient,
    plugin_id: &str,
) -> anyhow::Result<()> {
    println!("Installing plugin '{}'...", plugin_id);

    client.install_plugin(plugin_id)?;

    let plugin_file = client.plugin_dir().join(format!("{}.json", plugin_id));

    println!("✓ Plugin '{}' installed successfully!", plugin_id);
    println!("  Location: {}", plugin_file.display());

    Ok(())
}

fn cmd_plugin_uninstall(
    client: &marketplace::MarketplaceClient,
    plugin_id: &str,
) -> anyhow::Result<()> {
    let plugin_file = client.plugin_dir().join(format!("{}.json", plugin_id));

    if plugin_file.exists() {
        client.uninstall_plugin(plugin_id)?;
        println!("✓ Plugin '{}' uninstalled successfully!", plugin_id);
    } else {
        println!("⚠ Plugin '{}' not found", plugin_id);
    }

    Ok(())
}

fn cmd_plugin_list_installed(client: &marketplace::MarketplaceClient) -> anyhow::Result<()> {
    println!("Installed plugins:\n");

    let installed = client.list_installed()?;

    if installed.is_empty() {
        println!("  No plugins installed yet.");
        println!("\nBrowse plugins with: verdict plugin list");
        println!("Install a plugin with: verdict plugin install <plugin-id>");
        return Ok(());
    }

    for plugin in &installed {
        println!(
            "  {} v{} (installed: {})",
            plugin.name, plugin.version, plugin.installed_at
        );
    }

    Ok(())
}

fn get_plugin_dir() -> anyhow::Result<PathBuf> {
    if let Ok(cwd) = std::env::current_dir() {
        let local_plugins = cwd.join("plugins");
        if local_plugins.exists() {
            return Ok(local_plugins);
        }
    }

    if let Some(home) = dirs::home_dir() {
        let user_plugins = home.join(".verdict").join("plugins");
        if user_plugins.exists() {
            return Ok(user_plugins);
        }
    }

    Ok(PathBuf::from("plugins"))
}
