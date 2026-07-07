//! Plugin system — loads custom security rules from external files.
//!
//! Plugins are JSON files in `~/.verdict/plugins/` or `./plugins/` directory.
//! Each plugin file contains an array of security rules that are merged
//! with built-in rules during scanning.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// A single custom rule from a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRule {
    /// Unique code for the rule (e.g. "CUSTOM001")
    pub code: String,
    /// Human-readable name
    pub name: String,
    /// Regex pattern to match
    pub pattern: String,
    /// Severity level: "error", "warning", "info"
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Description of the issue
    pub message: String,
    /// Optional fix suggestion
    pub suggestion: Option<String>,
    /// Optional: only apply to specific languages (empty = all)
    #[serde(default)]
    pub languages: Vec<String>,
    /// Optional: file patterns to include (glob)
    #[serde(default)]
    pub include: Vec<String>,
    /// Optional: file patterns to exclude (glob)
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn default_severity() -> String {
    "warning".to_string()
}

/// A plugin file containing multiple rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFile {
    /// Plugin name
    pub name: String,
    /// Plugin version
    #[serde(default = "default_version")]
    pub version: String,
    /// Plugin description
    #[serde(default)]
    pub description: String,
    /// Rules in this plugin
    pub rules: Vec<PluginRule>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

/// Plugin loader that discovers and loads plugins from directories
pub struct PluginLoader {
    /// Directories to search for plugins
    plugin_dirs: Vec<PathBuf>,
}

impl PluginLoader {
    /// Create a new plugin loader with default plugin directories
    pub fn new() -> Self {
        let mut dirs = Vec::new();

        // User-level: ~/.verdict/plugins/
        if let Some(home) = dirs::home_dir() {
            dirs.push(home.join(".verdict").join("plugins"));
        }

        // Project-level: ./plugins/
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd.join("plugins"));
        }

        // Environment variable override
        if let Ok(env_dirs) = std::env::var("VERDICT_PLUGINS") {
            for dir in env_dirs.split(';').filter(|s| !s.is_empty()) {
                dirs.push(PathBuf::from(dir));
            }
        }

        Self { plugin_dirs: dirs }
    }

    /// Create a plugin loader with specific directories
    pub fn with_dirs(dirs: Vec<PathBuf>) -> Self {
        Self { plugin_dirs: dirs }
    }

    /// Load all plugins from configured directories
    pub fn load_all(&self) -> Result<Vec<PluginFile>> {
        let mut plugins = Vec::new();

        for dir in &self.plugin_dirs {
            if !dir.exists() || !dir.is_dir() {
                continue;
            }

            match self.load_from_dir(dir) {
                Ok(mut loaded) => plugins.append(&mut loaded),
                Err(e) => {
                    tracing::warn!("failed to load plugins from {}: {}", dir.display(), e);
                }
            }
        }

        tracing::info!(
            "loaded {} plugin(s) with {} total rules",
            plugins.len(),
            plugins.iter().map(|p| p.rules.len()).sum::<usize>()
        );

        Ok(plugins)
    }

    /// Load plugins from a single directory
    fn load_from_dir(&self, dir: &Path) -> Result<Vec<PluginFile>> {
        let mut plugins = Vec::new();

        let entries = fs::read_dir(dir)
            .with_context(|| format!("failed to read plugin dir: {}", dir.display()))?;

        for entry in entries.flatten() {
            let path = entry.path();

            // Only load .json files
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            match load_plugin_file(&path) {
                Ok(plugin) => {
                    tracing::debug!(
                        "loaded plugin '{}' v{} ({} rules)",
                        plugin.name,
                        plugin.version,
                        plugin.rules.len()
                    );
                    plugins.push(plugin);
                }
                Err(e) => {
                    tracing::warn!("failed to load plugin {}: {}", path.display(), e);
                }
            }
        }

        Ok(plugins)
    }
}

/// Load a single plugin file
fn load_plugin_file(path: &Path) -> Result<PluginFile> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read plugin file: {}", path.display()))?;

    let plugin: PluginFile = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse plugin file: {}", path.display()))?;

    // Validate each rule has a valid regex
    for rule in &plugin.rules {
        regex::Regex::new(&rule.pattern)
            .with_context(|| format!("invalid regex in rule '{}': {}", rule.code, rule.pattern))?;
    }

    Ok(plugin)
}

/// Generate a template plugin file
pub fn generate_template() -> String {
    let template = PluginFile {
        name: "my-custom-rules".to_string(),
        version: "0.1.0".to_string(),
        description: "Custom security rules for my project".to_string(),
        rules: vec![
            PluginRule {
                code: "CUSTOM001".to_string(),
                name: "No console.log in production".to_string(),
                pattern: r"console\.log\s*\(".to_string(),
                severity: "warning".to_string(),
                message: "console.log should not be in production code".to_string(),
                suggestion: Some("Use a proper logging library or remove debug output".to_string()),
                languages: vec!["javascript".to_string(), "typescript".to_string()],
                include: vec![],
                exclude: vec!["**/test/**".to_string()],
            },
            PluginRule {
                code: "CUSTOM002".to_string(),
                name: "No TODO without issue".to_string(),
                pattern: r"//\s*TODO(?!.*#\d+)".to_string(),
                severity: "info".to_string(),
                message: "TODO comment without issue reference".to_string(),
                suggestion: Some("Add issue number: // TODO #123".to_string()),
                languages: vec![],
                include: vec![],
                exclude: vec![],
            },
        ],
    };

    serde_json::to_string_pretty(&template).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_plugin(dir: &Path, filename: &str, content: &str) -> PathBuf {
        let path = dir.join(filename);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_load_valid_plugin() {
        let tmp = TempDir::new().unwrap();
        let json = r#"{
            "name": "test-plugin",
            "version": "1.0.0",
            "description": "test",
            "rules": [{
                "code": "TEST001",
                "name": "Test rule",
                "pattern": "TODO",
                "severity": "warning",
                "message": "Found TODO"
            }]
        }"#;
        create_test_plugin(tmp.path(), "test.json", json);

        let loader = PluginLoader::with_dirs(vec![tmp.path().to_path_buf()]);
        let plugins = loader.load_all().unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test-plugin");
        assert_eq!(plugins[0].rules.len(), 1);
        assert_eq!(plugins[0].rules[0].code, "TEST001");
    }

    #[test]
    fn test_load_multiple_plugins() {
        let tmp = TempDir::new().unwrap();
        create_test_plugin(
            tmp.path(),
            "a.json",
            r#"{
            "name": "plugin-a", "rules": [{
                "code": "A001", "name": "r1", "pattern": "foo", "message": "m"
            }]
        }"#,
        );
        create_test_plugin(
            tmp.path(),
            "b.json",
            r#"{
            "name": "plugin-b", "rules": [{
                "code": "B001", "name": "r2", "pattern": "bar", "message": "m"
            }]
        }"#,
        );

        let loader = PluginLoader::with_dirs(vec![tmp.path().to_path_buf()]);
        let plugins = loader.load_all().unwrap();
        assert_eq!(plugins.len(), 2);
    }

    #[test]
    fn test_skip_non_json_files() {
        let tmp = TempDir::new().unwrap();
        create_test_plugin(tmp.path(), "readme.txt", "not a plugin");
        create_test_plugin(
            tmp.path(),
            "valid.json",
            r#"{
            "name": "valid", "rules": [{
                "code": "V001", "name": "r", "pattern": "x", "message": "m"
            }]
        }"#,
        );

        let loader = PluginLoader::with_dirs(vec![tmp.path().to_path_buf()]);
        let plugins = loader.load_all().unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "valid");
    }

    #[test]
    fn test_invalid_regex_skipped() {
        let tmp = TempDir::new().unwrap();
        create_test_plugin(
            tmp.path(),
            "bad.json",
            r#"{
            "name": "bad-plugin", "rules": [{
                "code": "BAD001", "name": "bad", "pattern": "[invalid", "message": "m"
            }]
        }"#,
        );

        let loader = PluginLoader::with_dirs(vec![tmp.path().to_path_buf()]);
        let plugins = loader.load_all().unwrap();
        assert_eq!(plugins.len(), 0); // should be skipped
    }

    #[test]
    fn test_invalid_json_skipped() {
        let tmp = TempDir::new().unwrap();
        create_test_plugin(tmp.path(), "broken.json", "{not valid json");

        let loader = PluginLoader::with_dirs(vec![tmp.path().to_path_buf()]);
        let plugins = loader.load_all().unwrap();
        assert_eq!(plugins.len(), 0);
    }

    #[test]
    fn test_nonexistent_dir_ok() {
        let loader = PluginLoader::with_dirs(vec![PathBuf::from("/nonexistent/path/plugins")]);
        let plugins = loader.load_all().unwrap();
        assert_eq!(plugins.len(), 0);
    }

    #[test]
    fn test_plugin_rule_defaults() {
        let json = r#"{
            "name": "defaults-test",
            "rules": [{
                "code": "D001",
                "name": "minimal",
                "pattern": "test",
                "message": "found test"
            }]
        }"#;
        let tmp = TempDir::new().unwrap();
        create_test_plugin(tmp.path(), "defaults.json", json);

        let loader = PluginLoader::with_dirs(vec![tmp.path().to_path_buf()]);
        let plugins = loader.load_all().unwrap();
        let rule = &plugins[0].rules[0];
        assert_eq!(rule.severity, "warning"); // default
        assert!(rule.suggestion.is_none());
        assert!(rule.languages.is_empty());
    }

    #[test]
    fn test_generate_template_is_valid_json() {
        let template = generate_template();
        let parsed: Result<PluginFile, _> = serde_json::from_str(&template);
        assert!(parsed.is_ok());
        let plugin = parsed.unwrap();
        assert_eq!(plugin.rules.len(), 2);
    }
}
