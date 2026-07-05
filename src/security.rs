//! Security scanning module — detects common vulnerability patterns.

use crate::models::*;
use anyhow::Result;
use regex::Regex;
use std::fs;

use super::pipeline::Stage;

/// Security patterns to detect
struct SecurityPattern {
    regex: Regex,
    severity: Severity,
    code: String,
    message: String,
    suggestion: Option<String>,
}

impl SecurityPattern {
    fn new(
        pattern: &str,
        severity: Severity,
        code: &str,
        message: &str,
        suggestion: Option<&str>,
    ) -> Self {
        Self {
            regex: Regex::new(pattern).expect("invalid regex pattern"),
            severity,
            code: code.into(),
            message: message.into(),
            suggestion: suggestion.map(String::from),
        }
    }
}

/// Built-in security rules
fn builtin_rules() -> Vec<SecurityPattern> {
    vec![
        // SQL Injection patterns
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
        // XSS patterns
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
        // Hardcoded secrets
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
        // Weak crypto
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
        // Debug logging of sensitive data
        SecurityPattern::new(
            r"(?i)print\s*\(.*(?:password|secret|token|key)",
            Severity::Warning,
            "SEC005",
            "Debug print may leak sensitive data",
            Some("Remove debug prints before committing"),
        ),
        // Unsafe eval
        SecurityPattern::new(
            r"(?i)eval\s*\(",
            Severity::Error,
            "SEC006",
            "eval() is dangerous — potential code injection",
            Some("Use JSON.parse() or a safe alternative"),
        ),
        // Command injection
        SecurityPattern::new(
            r"(?i)(?:subprocess|exec|system|popen|os\.system).*\+",
            Severity::Error,
            "SEC007",
            "Potential command injection: string concatenation",
            Some("Use parameterized APIs or whitelist inputs"),
        ),
    ]
}

/// Stage that runs security pattern matching
pub struct SecurityStage {
    patterns: Vec<SecurityPattern>,
}

#[async_trait::async_trait]
impl Stage for SecurityStage {
    fn name(&self) -> &str {
        "security"
    }

    async fn execute(&self, input: &[AnalysisResult]) -> Result<Vec<AnalysisResult>> {
        let mut results = input.to_vec();

        for r in &mut results {
            let content = fs::read_to_string(&r.path).ok();
            if let Some(text) = content {
                for pattern in &self.patterns {
                    if pattern.regex.is_match(&text) {
                        r.findings.push(Finding {
                            category: Category::Security,
                            severity: pattern.severity,
                            code: pattern.code.clone(),
                            message: pattern.message.clone(),
                            file: r.path.clone(),
                            line: None,
                            column: None,
                            suggestion: pattern.suggestion.clone(),
                            ai_explanation: None,
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}

impl SecurityStage {
    pub fn new() -> Self {
        Self {
            patterns: builtin_rules(),
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
        let matches = patterns_match(
            "db.execute(\"SELECT * FROM users WHERE name = '\" + username + \"'\")"
        );
        assert!(matches.contains(&"SEC001".to_string()));
    }

    #[test]
    fn test_sql_injection_fstring() {
        let matches = patterns_match(
            "db.execute(f'SELECT * FROM users WHERE name = \"{username}\"')"
        );
        assert!(matches.contains(&"SEC001".to_string()));
    }

    #[test]
    fn test_no_sql_injection_safe() {
        let matches = patterns_match(
            "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        );
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
        let matches = patterns_match(
            "api_key = \"sk-abc123def456ghi789jkl012mno345\""
        );
        assert!(matches.contains(&"SEC003".to_string()));
    }

    #[test]
    fn test_hardcoded_password() {
        let matches = patterns_match(
            "password = \"super_secret_password_123\""
        );
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
        let matches = patterns_match(
            "subprocess.run('echo ' + user_input, shell=True)"
        );
        assert!(matches.contains(&"SEC007".to_string()));
    }

    #[test]
    fn test_no_command_injection_safe() {
        let matches = patterns_match(
            "subprocess.run(['echo', 'hello'])"
        );
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
        assert_eq!(builtin_rules().len(), 11);
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
}
