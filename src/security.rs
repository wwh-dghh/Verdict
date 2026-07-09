//! Security scanning module — detects common vulnerability patterns.

use crate::models::*;
use crate::plugin::PluginLoader;
use crate::wasm_plugin::WasmPluginLoader;
use anyhow::Result;
use regex::Regex;
use tokio::fs;

use super::pipeline::Stage;

/// Security patterns to detect
struct SecurityPattern {
    regex: Regex,
    severity: Severity,
    code: String,
    message: String,
    suggestion: Option<String>,
    languages: Vec<String>,
    include: Vec<String>,
    exclude: Vec<String>,
}

impl SecurityPattern {
    fn new(
        pattern: &str,
        severity: Severity,
        code: &str,
        message: &str,
        suggestion: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            regex: Regex::new(pattern)?,
            severity,
            code: code.into(),
            message: message.into(),
            suggestion: suggestion.map(String::from),
            languages: Vec::new(),
            include: Vec::new(),
            exclude: Vec::new(),
        })
    }
}

/// Simple glob-like pattern matching (supports *, **, and ?)
///
/// `*` matches any characters except path separators (`/`).
/// `**` matches any characters including path separators.
/// `?` matches any single character except path separators.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn matches(
        pattern: &[char],
        text: &[char],
        p: usize,
        t: usize,
        memo: &mut [Vec<Option<bool>>],
    ) -> bool {
        if p == pattern.len() {
            return t == text.len();
        }
        if let Some(result) = memo[p][t] {
            return result;
        }

        let result = match pattern[p] {
            '*' => {
                let is_double_star = p + 1 < pattern.len() && pattern[p + 1] == '*';
                if is_double_star {
                    // ** matches zero or more path segments
                    let next_p = p + 2;
                    // **/ can match the start
                    let slash_after = next_p < pattern.len() && pattern[next_p] == '/';
                    if slash_after && matches(pattern, text, next_p + 1, t, memo) {
                        true
                    } else {
                        // try matching ** at each position
                        (0..=text.len() - t).any(|i| matches(pattern, text, next_p, t + i, memo))
                    }
                } else {
                    // * matches anything except /
                    let next_p = p + 1;
                    // empty match
                    matches(pattern, text, next_p, t, memo)
                        || (t < text.len()
                            && text[t] != '/'
                            && matches(pattern, text, p, t + 1, memo))
                }
            }
            '?' => t < text.len() && text[t] != '/' && matches(pattern, text, p + 1, t + 1, memo),
            c => t < text.len() && c == text[t] && matches(pattern, text, p + 1, t + 1, memo),
        };

        memo[p][t] = Some(result);
        result
    }

    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    let mut memo = vec![vec![None; text_chars.len() + 1]; pattern_chars.len() + 1];
    matches(&pattern_chars, &text_chars, 0, 0, &mut memo)
}

/// Find the line number of the first regex match in the text
fn find_match_line(text: &str, regex: &Regex) -> Option<usize> {
    regex
        .find(text)
        .map(|m| text[..m.start()].chars().filter(|&c| c == '\n').count() + 1)
}

/// Built-in security rules
fn builtin_rules() -> Vec<SecurityPattern> {
    let patterns = [
        SecurityPattern::new(
            r#"(?i)(?:execute|query|exec)\s*\(\s*['"].*SELECT\s+.*['"]\s*\+"#,
            Severity::Error,
            "SEC001",
            "Potential SQL injection: string concatenation in query",
            Some("Use parameterized queries instead"),
        ),
        SecurityPattern::new(
            r#"(?i)(?:execute|query|exec)\s*\(f['"]"#,
            Severity::Error,
            "SEC001",
            "Potential SQL injection: f-string in query",
            Some("Use parameterized queries instead"),
        ),
        SecurityPattern::new(
            r"(?i)innerHTML\s*=",
            Severity::Error,
            "SEC002",
            "Potential XSS: setting innerHTML",
            Some("Use textContent or a sanitization library"),
        ),
        SecurityPattern::new(
            r"(?i)document\.write\s*\(",
            Severity::Warning,
            "SEC002",
            "Potential XSS: document.write()",
            Some("Use DOM manipulation methods instead"),
        ),
        SecurityPattern::new(
            r#"(?i)(?:api[_-]?key|secret[_-]?key|password|token)\s*[:=]\s*['"]\w{8,}['"]"#,
            Severity::Error,
            "SEC003",
            "Possible hardcoded secret detected",
            Some("Use environment variables or a secrets manager"),
        ),
        SecurityPattern::new(
            r"(?:AKIA|sk-[a-zA-Z0-9]{20,})",
            Severity::Error,
            "SEC003",
            "Possible AWS/access key detected",
            Some("Move credentials to environment variables"),
        ),
        SecurityPattern::new(
            r"(?i)md5(?:hash|sum|5)?\s*\(",
            Severity::Warning,
            "SEC004",
            "Weak hash function (MD5) detected",
            Some("Use SHA-256 or bcrypt for password hashing"),
        ),
        SecurityPattern::new(
            r"(?i)DES(?:ede)?\s*(?:Encrypt|Cipher|\.new)",
            Severity::Warning,
            "SEC004",
            "Weak encryption algorithm (DES) detected",
            Some("Use AES-256-GCM instead"),
        ),
        SecurityPattern::new(
            r"(?i)print\s*\(.*(?:password|secret|token|key)",
            Severity::Warning,
            "SEC005",
            "Debug print may leak sensitive data",
            Some("Remove debug prints before committing"),
        ),
        SecurityPattern::new(
            r"(?i)eval\s*\(",
            Severity::Error,
            "SEC006",
            "eval() is dangerous — potential code injection",
            Some("Use JSON.parse() or a safe alternative"),
        ),
        SecurityPattern::new(
            r"(?i)(?:subprocess|exec|system|popen|os\.system).*\+",
            Severity::Error,
            "SEC007",
            "Potential command injection: string concatenation",
            Some("Use parameterized APIs or whitelist inputs"),
        ),
        SecurityPattern::new(
            r"(?i)(?:\.\./|\\\.\.|%2e%2e)",
            Severity::Error,
            "SEC008",
            "Potential path traversal vulnerability",
            Some("Validate and sanitize user-provided paths"),
        ),
        SecurityPattern::new(
            r"(?i)(?:http[s]?://|ftp://).*\$\w+",
            Severity::Error,
            "SEC009",
            "Potential SSRF: dynamic URL construction",
            Some("Validate URLs against an allowlist"),
        ),
    ];

    patterns.into_iter().filter_map(|p| p.ok()).collect()
}

/// Stage that runs security pattern matching
pub struct SecurityStage {
    patterns: Vec<SecurityPattern>,
    wasm_plugins: Vec<crate::wasm_plugin::WasmPlugin>,
}

#[async_trait::async_trait]
impl Stage for SecurityStage {
    fn name(&self) -> &str {
        "security"
    }

    async fn execute(&self, input: &[AnalysisResult]) -> Result<Vec<AnalysisResult>> {
        let mut results = input.to_vec();

        for r in &mut results {
            let content = fs::read_to_string(&r.path).await.ok();
            if let Some(text) = content {
                for pattern in &self.patterns {
                    // Check language filter
                    if !pattern.languages.is_empty() {
                        if let Some(lang) = r.language {
                            let lang_str = format!("{:?}", lang).to_lowercase();
                            if !pattern
                                .languages
                                .iter()
                                .any(|l| l.to_lowercase() == lang_str)
                            {
                                continue;
                            }
                        }
                    }

                    // Check file include/exclude patterns
                    let path_str = r.path.to_string_lossy();
                    if !pattern.include.is_empty() {
                        let matches_include =
                            pattern.include.iter().any(|p| glob_match(p, &path_str));
                        if !matches_include {
                            continue;
                        }
                    }
                    if !pattern.exclude.is_empty() {
                        let matches_exclude =
                            pattern.exclude.iter().any(|p| glob_match(p, &path_str));
                        if matches_exclude {
                            continue;
                        }
                    }

                    if pattern.regex.is_match(&text) {
                        let line_num = find_match_line(&text, &pattern.regex);
                        r.findings.push(Finding {
                            category: Category::Security,
                            severity: pattern.severity,
                            code: pattern.code.clone(),
                            message: pattern.message.clone(),
                            file: r.path.clone(),
                            line: line_num,
                            column: None,
                            suggestion: pattern.suggestion.clone(),
                            ai_explanation: None,
                        });
                    }
                }

                // Execute WASM plugins
                for plugin in &self.wasm_plugins {
                    match plugin.execute_rules(&text, &r.path.to_string_lossy()) {
                        Ok(findings) => {
                            r.findings.extend(findings);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "WASM plugin execution failed for {}: {}",
                                r.path.display(),
                                e
                            );
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}

impl SecurityStage {
    /// Create a new security stage with built-in rules and loaded plugins
    pub fn new() -> Self {
        let mut patterns = builtin_rules();

        // Load plugin rules
        let loader = PluginLoader::new();
        match loader.load_all() {
            Ok(plugins) => {
                for plugin in plugins {
                    for rule in plugin.rules {
                        match Regex::new(&rule.pattern) {
                            Ok(regex) => {
                                let severity = match rule.severity.to_lowercase().as_str() {
                                    "error" => Severity::Error,
                                    "warning" => Severity::Warning,
                                    _ => Severity::Info,
                                };
                                patterns.push(SecurityPattern {
                                    regex,
                                    severity,
                                    code: rule.code,
                                    message: rule.message,
                                    suggestion: rule.suggestion,
                                    languages: rule.languages,
                                    include: rule.include,
                                    exclude: rule.exclude,
                                });
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "invalid regex in plugin rule '{}': {}",
                                    rule.code,
                                    e
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!("no plugins loaded: {}", e);
            }
        }

        // Load WASM plugins
        let wasm_loader = WasmPluginLoader::new();
        let wasm_plugins = match wasm_loader.load_all() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("failed to load WASM plugins: {}", e);
                Vec::new()
            }
        };

        tracing::info!(
            "security stage initialized: {} regex patterns, {} WASM plugins",
            patterns.len(),
            wasm_plugins.len()
        );

        Self {
            patterns,
            wasm_plugins,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns_match(text: &str) -> Vec<String> {
        builtin_rules()
            .into_iter()
            .filter(|p| p.regex.is_match(text))
            .map(|p| p.code)
            .collect()
    }

    #[test]
    fn test_sql_injection_concatenation() {
        let matches =
            patterns_match("db.execute(\"SELECT * FROM users WHERE name = '\" + username + \"'\")");
        assert!(matches.contains(&"SEC001".to_string()));
    }

    #[test]
    fn test_sql_injection_fstring() {
        let matches =
            patterns_match("db.execute(f'SELECT * FROM users WHERE name = \"{username}\"')");
        assert!(matches.contains(&"SEC001".to_string()));
    }

    #[test]
    fn test_no_sql_injection_safe() {
        let matches =
            patterns_match("cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))");
        assert!(!matches.contains(&"SEC001".to_string()));
    }

    #[test]
    fn test_xss_innerhtml() {
        let matches = patterns_match("element.innerHTML = userInput");
        assert!(matches.contains(&"SEC002".to_string()));
    }

    #[test]
    fn test_xss_document_write() {
        let matches = patterns_match("document.write(html)");
        assert!(matches.contains(&"SEC002".to_string()));
    }

    #[test]
    fn test_hardcoded_api_key() {
        let matches = patterns_match("api_key = \"sk-abc123def456ghi789jkl012mno345\"");
        assert!(matches.contains(&"SEC003".to_string()));
    }

    #[test]
    fn test_hardcoded_password() {
        let matches = patterns_match("password = \"super_secret_password_123\"");
        assert!(matches.contains(&"SEC003".to_string()));
    }

    #[test]
    fn test_no_hardcoded_secret_safe() {
        let matches = patterns_match("api_key = os.environ['API_KEY']");
        assert!(!matches.contains(&"SEC003".to_string()));
    }

    #[test]
    fn test_md5_hash() {
        let matches = patterns_match("hashed = hashlib.md5(data).hexdigest()");
        assert!(matches.contains(&"SEC004".to_string()));
    }

    #[test]
    fn test_des_encryption() {
        let matches = patterns_match("cipher = DES.new(key, DES.MODE_CBC)");
        assert!(matches.contains(&"SEC004".to_string()));
    }

    #[test]
    fn test_eval_usage() {
        let matches = patterns_match("result = eval(user_input)");
        assert!(matches.contains(&"SEC006".to_string()));
    }

    #[test]
    fn test_no_eval_safe() {
        let matches = patterns_match("result = json.loads(user_input)");
        assert!(!matches.contains(&"SEC006".to_string()));
    }

    #[test]
    fn test_command_injection() {
        let matches = patterns_match("subprocess.run('echo ' + user_input, shell=True)");
        assert!(matches.contains(&"SEC007".to_string()));
    }

    #[test]
    fn test_no_command_injection_safe() {
        let matches = patterns_match("subprocess.run(['echo', 'hello'])");
        assert!(!matches.contains(&"SEC007".to_string()));
    }

    #[test]
    fn test_debug_log_leak() {
        let matches = patterns_match("print(f'password: {password}')");
        assert!(matches.contains(&"SEC005".to_string()));
    }

    #[test]
    fn test_no_debug_log_safe() {
        let matches = patterns_match("print('done')");
        assert!(!matches.contains(&"SEC005".to_string()));
    }

    #[test]
    fn test_builtin_rules_count() {
        assert_eq!(builtin_rules().len(), 13);
    }

    #[test]
    fn test_no_false_positive_clean_code() {
        let clean = r#"
import os
from flask import Flask

app = Flask(__name__)

@app.route('/user/<id>')
def get_user(id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (id,))
    return str(cursor.fetchone())
"#;
        let matches = patterns_match(clean);
        assert!(matches.is_empty(), "clean code triggered: {:?}", matches);
    }

    #[test]
    fn test_find_match_line_single_line() {
        let text = "hello world";
        let re = Regex::new("world").unwrap();
        assert_eq!(find_match_line(text, &re), Some(1));
    }

    #[test]
    fn test_find_match_line_multiline() {
        let text = "line 1\nline 2\npassword = 'secret'\nline 4";
        let re = Regex::new(r"password\s*=").unwrap();
        assert_eq!(find_match_line(text, &re), Some(3));
    }

    #[test]
    fn test_find_match_line_no_match() {
        let text = "safe code here";
        let re = Regex::new("eval").unwrap();
        assert_eq!(find_match_line(text, &re), None);
    }

    #[test]
    fn test_find_match_line_first_line() {
        let text = "eval(user_input)\nmore code";
        let re = Regex::new(r"eval\s*\(").unwrap();
        assert_eq!(find_match_line(text, &re), Some(1));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("test.py", "test.py"));
        assert!(!glob_match("test.py", "test.js"));
    }

    #[test]
    fn test_glob_match_single_char() {
        assert!(glob_match("test.?s", "test.js"));
        assert!(glob_match("test.?s", "test.ts"));
        assert!(!glob_match("test.?s", "test.py"));
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*.py", "test.py"));
        assert!(!glob_match("*.py", "src/test.py"));
        assert!(!glob_match("*.py", "test.js"));
    }

    #[test]
    fn test_glob_match_path() {
        assert!(glob_match("**/test/**", "src/test/main.py"));
        assert!(glob_match("src/*.rs", "src/main.rs"));
        assert!(!glob_match("src/*.rs", "src/mod/main.rs"));
    }

    #[test]
    fn test_glob_match_empty_pattern() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "test"));
    }

    #[test]
    fn test_glob_match_star_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn test_glob_match_double_star_at_end() {
        assert!(glob_match("src/**", "src/a/b.rs"));
        assert!(glob_match("src/**", "src/file.rs"));
        assert!(!glob_match("src/**", "other/file.rs"));
    }

    #[test]
    fn test_glob_match_double_star_at_start() {
        assert!(glob_match("**/test", "src/test"));
        assert!(glob_match("**/test", "a/b/test"));
    }
}
