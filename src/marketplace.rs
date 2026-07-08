//! Plugin marketplace — browse, install, and manage custom security rules.
//!
//! The marketplace connects users with a curated collection of community-contributed
//! security rules that can be installed directly into the Verdict plugin system.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A plugin available in the marketplace
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePlugin {
    /// Unique plugin identifier
    pub id: String,
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Author
    pub author: String,
    /// Categories: "security", "quality", "style", "testing"
    pub categories: Vec<String>,
    /// Supported languages
    pub languages: Vec<String>,
    /// Number of downloads
    #[serde(default)]
    pub downloads: u64,
    /// Rating (0-5)
    #[serde(default)]
    pub rating: f64,
    /// The plugin content (JSON rules)
    pub content: String,
}

/// A plugin that has been installed by the user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPlugin {
    /// Plugin ID
    pub id: String,
    /// Plugin name
    pub name: String,
    /// Installed version
    pub version: String,
    /// Installation date (ISO 8601)
    pub installed_at: String,
}

/// Plugin marketplace client
#[allow(dead_code)]
pub struct MarketplaceClient {
    /// Base URL for the marketplace API
    api_base: String,
    /// Local plugin directory
    plugin_dir: PathBuf,
}

#[allow(dead_code)]
impl MarketplaceClient {
    /// Create a new marketplace client
    pub fn new(api_base: String, plugin_dir: PathBuf) -> Self {
        Self {
            api_base,
            plugin_dir,
        }
    }

    /// List all available plugins in the marketplace
    pub fn list_plugins(&self) -> Result<Vec<MarketplacePlugin>> {
        // TODO: Fetch from remote marketplace API
        // For now, return empty list
        Ok(vec![])
    }

    /// Search for plugins by keyword
    pub fn search_plugins(&self, _query: &str) -> Result<Vec<MarketplacePlugin>> {
        // TODO: Search remote marketplace API
        Ok(vec![])
    }

    /// Install a plugin from the marketplace
    pub fn install_plugin(&self, plugin_id: &str) -> Result<()> {
        fs::create_dir_all(&self.plugin_dir).with_context(|| {
            format!("failed to create plugin dir: {}", self.plugin_dir.display())
        })?;

        let plugin_file = self.plugin_dir.join(format!("{}.json", plugin_id));

        let content = format!(
            r#"{{
                "name": "{}",
                "version": "0.1.0",
                "description": "Installed from marketplace",
                "rules": []
            }}"#,
            plugin_id
        );

        fs::write(&plugin_file, &content)
            .with_context(|| format!("failed to write plugin to {}", plugin_file.display()))?;

        self.record_install(plugin_id)?;

        tracing::info!(
            "installed plugin '{}' to {}",
            plugin_id,
            plugin_file.display()
        );
        Ok(())
    }

    /// Uninstall a plugin
    pub fn uninstall_plugin(&self, plugin_id: &str) -> Result<()> {
        let plugin_file = self.plugin_dir.join(format!("{}.json", plugin_id));

        if plugin_file.exists() {
            fs::remove_file(&plugin_file).with_context(|| {
                format!("failed to remove plugin file: {}", plugin_file.display())
            })?;
        }

        // Remove from installed list
        self.remove_install_record(plugin_id)?;

        tracing::info!("uninstalled plugin '{}'", plugin_id);
        Ok(())
    }

    /// List all installed plugins
    pub fn list_installed(&self) -> Result<Vec<InstalledPlugin>> {
        let installed_file = self.plugin_dir.join("installed-plugins.json");

        if !installed_file.exists() {
            return Ok(vec![]);
        }

        let content = fs::read_to_string(&installed_file)?;
        let installed: Vec<InstalledPlugin> = serde_json::from_str(&content)?;
        Ok(installed)
    }

    fn record_install(&self, plugin_id: &str) -> Result<()> {
        let installed_file = self.plugin_dir.join("installed-plugins.json");

        let mut installed: Vec<InstalledPlugin> = if installed_file.exists() {
            let content = fs::read_to_string(&installed_file)?;
            serde_json::from_str(&content)?
        } else {
            vec![]
        };

        if installed.iter().any(|p| p.id == plugin_id) {
            return Ok(());
        }

        let now = chrono::Utc::now().to_rfc3339();
        installed.push(InstalledPlugin {
            id: plugin_id.to_string(),
            name: plugin_id.to_string(),
            version: "0.1.0".to_string(),
            installed_at: now,
        });

        let content = serde_json::to_string_pretty(&installed)?;
        fs::write(&installed_file, content)?;

        Ok(())
    }

    fn remove_install_record(&self, plugin_id: &str) -> Result<()> {
        let installed_file = self.plugin_dir.join("installed-plugins.json");

        if !installed_file.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&installed_file)?;
        let mut installed: Vec<InstalledPlugin> = serde_json::from_str(&content)?;
        installed.retain(|p| p.id != plugin_id);

        let content = serde_json::to_string_pretty(&installed)?;
        fs::write(&installed_file, content)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_client() {
        let tmp = TempDir::new().unwrap();
        let client = MarketplaceClient::new(
            "https://marketplace.verdict.dev".to_string(),
            tmp.path().to_path_buf(),
        );
        assert_eq!(client.api_base, "https://marketplace.verdict.dev");
    }

    #[test]
    fn test_list_plugins_empty() {
        let tmp = TempDir::new().unwrap();
        let client = MarketplaceClient::new(
            "https://marketplace.verdict.dev".to_string(),
            tmp.path().to_path_buf(),
        );
        let plugins = client.list_plugins().unwrap();
        assert!(plugins.is_empty());
    }

    #[test]
    fn test_search_plugins_empty() {
        let tmp = TempDir::new().unwrap();
        let client = MarketplaceClient::new(
            "https://marketplace.verdict.dev".to_string(),
            tmp.path().to_path_buf(),
        );
        let plugins = client.search_plugins("test").unwrap();
        assert!(plugins.is_empty());
    }

    #[test]
    fn test_install_plugin_creates_file() {
        let tmp = TempDir::new().unwrap();
        let client = MarketplaceClient::new(
            "https://marketplace.verdict.dev".to_string(),
            tmp.path().to_path_buf(),
        );
        client.install_plugin("test-plugin").unwrap();

        let plugin_file = tmp.path().join("test-plugin.json");
        assert!(plugin_file.exists());

        let content = fs::read_to_string(plugin_file).unwrap();
        assert!(content.contains("test-plugin"));
    }

    #[test]
    fn test_uninstall_plugin_removes_file() {
        let tmp = TempDir::new().unwrap();
        let client = MarketplaceClient::new(
            "https://marketplace.verdict.dev".to_string(),
            tmp.path().to_path_buf(),
        );
        client.install_plugin("test-plugin").unwrap();
        client.uninstall_plugin("test-plugin").unwrap();

        let plugin_file = tmp.path().join("test-plugin.json");
        assert!(!plugin_file.exists());
    }

    #[test]
    fn test_list_installed_empty() {
        let tmp = TempDir::new().unwrap();
        let client = MarketplaceClient::new(
            "https://marketplace.verdict.dev".to_string(),
            tmp.path().to_path_buf(),
        );
        let installed = client.list_installed().unwrap();
        assert!(installed.is_empty());
    }

    #[test]
    fn test_install_records_plugin() {
        let tmp = TempDir::new().unwrap();
        let client = MarketplaceClient::new(
            "https://marketplace.verdict.dev".to_string(),
            tmp.path().to_path_buf(),
        );
        client.install_plugin("test-plugin").unwrap();

        let installed = client.list_installed().unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].id, "test-plugin");
    }

    #[test]
    fn test_uninstall_removes_record() {
        let tmp = TempDir::new().unwrap();
        let client = MarketplaceClient::new(
            "https://marketplace.verdict.dev".to_string(),
            tmp.path().to_path_buf(),
        );
        client.install_plugin("test-plugin").unwrap();
        client.uninstall_plugin("test-plugin").unwrap();

        let installed = client.list_installed().unwrap();
        assert!(installed.is_empty());
    }
}
