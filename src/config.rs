//! Configuration loading — reads from config file and CLI args.

use crate::models::{Config, Language, OutputFormat};
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

/// Loads configuration from file or returns defaults
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load config from .verdict.yaml if it exists
    pub fn load() -> Result<Config> {
        let mut config = Config::default();

        // Try to find config file in current dir or home dir
        let config_paths: Vec<Option<PathBuf>> = vec![
            Some(PathBuf::from(".verdict.yaml")),
            Some(PathBuf::from(".verdict.yml")),
            Some(PathBuf::from(".verdict.json")),
            dirs::config_dir().map(|d| d.join("verdict").join("config.yaml")),
        ];

        for path in config_paths.into_iter().flatten() {
            if path.exists() {
                let content = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read config: {}", path.display()))?;

                let loaded: Config = if path.extension().is_some_and(|e| e == "json") {
                    serde_json::from_str(&content)
                        .with_context(|| "failed to parse config as JSON")?
                } else {
                    serde_yaml::from_str(&content)
                        .with_context(|| "failed to parse config as YAML")?
                };

                // Merge loaded config into defaults
                if !loaded.targets.is_empty() {
                    config.targets = loaded.targets;
                }
                if !loaded.languages.is_empty() {
                    config.languages = loaded.languages;
                }
                if !loaded.linters.is_empty() {
                    config.linters = loaded.linters;
                }
                config.security_scan = loaded.security_scan;
                config.ai_review = loaded.ai_review;
                if loaded.llm.is_some() {
                    config.llm = loaded.llm;
                }
                config.output = loaded.output;
                config.diff_mode = loaded.diff_mode;
                if !loaded.ignore.is_empty() {
                    config.ignore = loaded.ignore;
                }
                if !loaded.thresholds.is_default() {
                    config.thresholds = loaded.thresholds;
                }

                tracing::info!("loaded config from {}", path.display());
                break;
            }
        }

        Ok(config)
    }
}

/// Merges CLI overrides with loaded config
pub fn merge_config(mut config: Config, overrides: CliOverrides) -> Config {
    if let Some(langs) = overrides.languages {
        config.languages = langs;
    }
    if let Some(format) = overrides.output_format {
        config.output = format;
    }
    if overrides.ai_review {
        config.ai_review = true;
    }
    if overrides.diff_mode {
        config.diff_mode = true;
    }
    if overrides.fix {
        tracing::warn!("--fix is experimental and not yet implemented");
    }
    config
}

/// CLI-provided overrides (populated from clap args)
#[derive(Default)]
pub struct CliOverrides {
    pub languages: Option<Vec<Language>>,
    pub output_format: Option<OutputFormat>,
    pub ai_review: bool,
    pub diff_mode: bool,
    pub fix: bool,
}
