//! WASM plugin runtime — loads and executes WASM plugins for advanced security rules.
//!
//! Plugins are compiled WASM modules that implement a simple interface for
//! defining custom security rules. They run in a sandboxed environment.

use anyhow::{Context, Result};
use std::path::Path;

/// A WASM plugin that provides custom security rules
pub struct WasmPlugin {
    #[allow(dead_code)] // needed when instantiating modules for rule execution
    engine: wasmtime::Engine,
    #[allow(dead_code)] // kept for upcoming rule invocation
    module: wasmtime::Module,
    name: String,
    #[allow(dead_code)] // populated from WASM metadata when supported
    version: String,
}

impl WasmPlugin {
    /// Load a WASM plugin from a file
    pub fn from_file(path: &Path) -> Result<Self> {
        let engine = wasmtime::Engine::default();
        let wasm_bytes = std::fs::read(path)
            .with_context(|| format!("failed to read WASM plugin: {}", path.display()))?;

        let module = wasmtime::Module::new(&engine, &wasm_bytes)
            .with_context(|| format!("failed to compile WASM module: {}", path.display()))?;

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            engine,
            module,
            name,
            version: "1.0.0".to_string(), // TODO: read from WASM metadata
        })
    }

    /// Plugin display name (derived from the file stem)
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Plugin semantic version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Execute the plugin's rules against the given text
    pub fn execute_rules(
        &self,
        _text: &str,
        _file_path: &str,
    ) -> Result<Vec<crate::models::Finding>> {
        // TODO: Implement actual WASM plugin execution
        // This is a skeleton — the full implementation would:
        // 1. Instantiate the WASM module
        // 2. Call the plugin's rule evaluation function
        // 3. Parse the results into Finding structs
        // 4. Handle errors gracefully
        Ok(vec![])
    }
}

/// Plugin loader that discovers and loads WASM plugins
pub struct WasmPluginLoader {
    plugin_dirs: Vec<std::path::PathBuf>,
}

impl Default for WasmPluginLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmPluginLoader {
    /// Create a new WASM plugin loader
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

        Self { plugin_dirs: dirs }
    }

    /// Return the configured plugin directories (read-only)
    pub fn plugin_dirs(&self) -> &[std::path::PathBuf] {
        &self.plugin_dirs
    }

    /// Create a WASM plugin loader with specific directories
    #[allow(dead_code)] // public constructor for embedders and tests
    pub fn with_dirs(dirs: Vec<std::path::PathBuf>) -> Self {
        Self { plugin_dirs: dirs }
    }

    /// Load all WASM plugins from configured directories
    pub fn load_all(&self) -> Result<Vec<WasmPlugin>> {
        let mut plugins = Vec::new();

        for dir in &self.plugin_dirs {
            if !dir.exists() || !dir.is_dir() {
                continue;
            }

            match self.load_from_dir(dir) {
                Ok(mut loaded) => plugins.append(&mut loaded),
                Err(e) => {
                    tracing::warn!("failed to load WASM plugins from {}: {}", dir.display(), e);
                }
            }
        }

        tracing::info!("loaded {} WASM plugin(s)", plugins.len());

        Ok(plugins)
    }

    fn load_from_dir(&self, dir: &Path) -> Result<Vec<WasmPlugin>> {
        let mut plugins = Vec::new();

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("failed to read plugin dir: {}", dir.display()))?;

        for entry in entries.flatten() {
            let path = entry.path();

            // Only load .wasm files
            if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                continue;
            }

            match WasmPlugin::from_file(&path) {
                Ok(plugin) => {
                    tracing::debug!("loaded WASM plugin '{}'", plugin.name);
                    plugins.push(plugin);
                }
                Err(e) => {
                    tracing::warn!("failed to load WASM plugin {}: {}", path.display(), e);
                }
            }
        }

        Ok(plugins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_loader_creates_new_instance() {
        let loader = WasmPluginLoader::new();
        // Should not panic
        assert!(loader.load_all().is_ok());
    }

    #[test]
    fn test_loader_with_nonexistent_dir() {
        let loader = WasmPluginLoader {
            plugin_dirs: vec![PathBuf::from("/nonexistent/path/plugins")],
        };
        let plugins = loader.load_all().unwrap();
        assert_eq!(plugins.len(), 0);
    }

    #[test]
    fn test_loader_skips_non_wasm_files() {
        let tmp = TempDir::new().unwrap();
        let mut file = std::fs::File::create(tmp.path().join("test.json")).unwrap();
        file.write_all(b"{}").unwrap();

        let loader = WasmPluginLoader {
            plugin_dirs: vec![tmp.path().to_path_buf()],
        };
        let plugins = loader.load_all().unwrap();
        assert_eq!(plugins.len(), 0); // no .wasm files
    }

    #[test]
    fn test_wasm_plugin_from_file_not_found() {
        let result = WasmPlugin::from_file(Path::new("/nonexistent.wasm"));
        assert!(result.is_err());
    }

    #[test]
    fn test_with_dirs() {
        let dirs = vec![PathBuf::from("/tmp/wasm-plugins")];
        let loader = WasmPluginLoader::with_dirs(dirs.clone());
        assert_eq!(loader.plugin_dirs(), &dirs[..]);
    }
}
