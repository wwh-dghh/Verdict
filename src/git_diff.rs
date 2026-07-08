//! Git diff integration — discovers changed files for incremental analysis.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Represents the diff source for incremental analysis
#[allow(dead_code)] // Variants are part of the public API for future CLI flags
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSource {
    /// Changes staged for commit (git diff --cached)
    Staged,
    /// Unstaged working tree changes (git diff)
    WorkingTree,
    /// All uncommitted changes (staged + unstaged)
    #[default]
    All,
}

/// Options for git diff file discovery
#[derive(Debug, Clone)]
pub struct DiffOptions {
    /// The diff source to compare against
    pub source: DiffSource,
    /// Only return files with supported extensions
    pub supported_only: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            source: DiffSource::All,
            supported_only: true,
        }
    }
}

/// Discover changed files using git diff
///
/// Returns paths relative to the repository root.
/// Falls back gracefully if not in a git repository.
pub fn discover_changed_files(repo_root: &Path, opts: &DiffOptions) -> Result<Vec<PathBuf>> {
    let output = match opts.source {
        DiffSource::Staged => run_git_diff(
            repo_root,
            &["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        ),
        DiffSource::WorkingTree => {
            run_git_diff(repo_root, &["diff", "--name-only", "--diff-filter=ACMR"])
        }
        DiffSource::All => {
            let staged = run_git_diff(
                repo_root,
                &["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            );
            let working = run_git_diff(repo_root, &["diff", "--name-only", "--diff-filter=ACMR"]);

            let staged_files = match staged {
                Ok(o) => parse_diff_output(&o),
                Err(_) => Vec::new(),
            };
            let working_files = match working {
                Ok(o) => parse_diff_output(&o),
                Err(_) => Vec::new(),
            };

            let mut all: Vec<PathBuf> = staged_files;
            for f in working_files {
                if !all.contains(&f) {
                    all.push(f);
                }
            }
            return Ok(all);
        }
    };

    let output = output?;
    let files = parse_diff_output(&output);

    if opts.supported_only {
        let supported: Vec<PathBuf> = files
            .into_iter()
            .filter(|p| crate::models::Language::from_path(p).is_some())
            .collect();
        Ok(supported)
    } else {
        Ok(files)
    }
}

/// Get the git repository root from a given path
pub fn find_repo_root(from: &Path) -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .current_dir(from)
        .output()
        .context("failed to run git rev-parse")?;

    if !output.status.success() {
        anyhow::bail!(
            "not a git repository (or any parent up to root): {}",
            from.display()
        );
    }

    let root = String::from_utf8(output.stdout)
        .context("git rev-parse output is not valid UTF-8")?
        .trim()
        .to_string();

    Ok(PathBuf::from(root))
}

/// Check if the given path is inside a git repository
pub fn is_git_repo(path: &Path) -> bool {
    std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--is-inside-work-tree")
        .current_dir(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_git_diff(repo_root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .context("failed to run git diff")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git diff failed: {}", stderr);
    }

    Ok(output.stdout)
}

fn parse_diff_output(output: &[u8]) -> Vec<PathBuf> {
    let text = String::from_utf8_lossy(output);
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_diff_output_single_file() {
        let output = b"src/main.rs\n";
        let files = parse_diff_output(output);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("src/main.rs"));
    }

    #[test]
    fn test_parse_diff_output_multiple_files() {
        let output = b"src/main.rs\nsrc/lib.rs\nCargo.toml\n";
        let files = parse_diff_output(output);
        assert_eq!(files.len(), 3);
        assert_eq!(files[0], PathBuf::from("src/main.rs"));
        assert_eq!(files[1], PathBuf::from("src/lib.rs"));
        assert_eq!(files[2], PathBuf::from("Cargo.toml"));
    }

    #[test]
    fn test_parse_diff_output_empty() {
        let output = b"";
        let files = parse_diff_output(output);
        assert!(files.is_empty());
    }

    #[test]
    fn test_parse_diff_output_whitespace_lines() {
        let output = b"src/main.rs\n\n  \nsrc/lib.rs\n";
        let files = parse_diff_output(output);
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_diff_options_default() {
        let opts = DiffOptions::default();
        assert_eq!(opts.source, DiffSource::All);
        assert!(opts.supported_only);
    }

    #[test]
    fn test_diff_source_staged() {
        assert_eq!(DiffSource::Staged, DiffSource::Staged);
        assert_ne!(DiffSource::Staged, DiffSource::WorkingTree);
    }

    #[test]
    fn test_is_git_repo_current_dir() {
        // verdict is inside a git repo (beacon-cloud)
        let cwd = std::env::current_dir().unwrap_or_default();
        // This may or may not be true depending on the test environment
        // but the function should not panic
        let _result = is_git_repo(&cwd);
    }

    #[test]
    fn test_is_git_repo_nonexistent_dir() {
        assert!(!is_git_repo(Path::new(
            "/nonexistent/path/that/does/not/exist"
        )));
    }

    #[test]
    fn test_find_repo_root_nonexistent() {
        let result = find_repo_root(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_diff_output_with_rename() {
        // git diff --name-only shows the new path for renames
        let output = b"src/new_name.rs\n";
        let files = parse_diff_output(output);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("src/new_name.rs"));
    }
}
