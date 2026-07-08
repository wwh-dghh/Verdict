//! AI Semantic review stage — LLM-as-Judge for deeper code analysis.

use crate::models::*;
use anyhow::Result;
use std::fs;

use super::pipeline::Stage;

/// Stage that sends code to an LLM for semantic review
pub struct SemanticStage {
    llm_config: Option<LLMConfig>,
}

#[async_trait::async_trait]
impl Stage for SemanticStage {
    fn name(&self) -> &str {
        "semantic"
    }

    async fn execute(&self, input: &[AnalysisResult]) -> Result<Vec<AnalysisResult>> {
        let mut results = input.to_vec();

        let Some(ref config) = self.llm_config else {
            tracing::info!("LLM config not provided, skipping semantic review");
            return Ok(results);
        };

        for r in &mut results {
            let content = fs::read_to_string(&r.path).ok();
            if let Some(text) = content {
                // Limit to first 4000 chars to avoid token limits
                let snippet: String = text.chars().take(4000).collect();

                let lang_name = r
                    .language
                    .map(|l| format!("{:?}", l).to_lowercase())
                    .unwrap_or_else(|| "unknown".to_string());

                let prompt = format!(
                    "Review this {} code for AI-generated code quality issues:\n\n{}\n\n\n\
                     Check for:\n\
                     - Overly verbose or unnecessary abstractions\n\
                     - Missing error handling\n\
                     - Unreasonable dependency choices\n\
                     - Template-like or boilerplate code\n\
                     - Logic that looks correct but has subtle bugs\n\
                     - Lack of edge case handling\n\n\
                     Rate on a scale of 0-100 and provide a brief explanation.",
                    lang_name, snippet
                );

                let response = call_llm(config, &prompt).await;
                if let Some(ai_text) = response {
                    r.findings.push(Finding {
                        category: Category::AiSemantic,
                        severity: Severity::Info,
                        code: "SEM001".into(),
                        message: "AI semantic review completed".into(),
                        file: r.path.clone(),
                        line: None,
                        column: None,
                        suggestion: None,
                        ai_explanation: Some(ai_text),
                    });
                }
            }
        }

        Ok(results)
    }
}

impl SemanticStage {
    pub fn new(llm_config: Option<LLMConfig>) -> Self {
        Self { llm_config }
    }
}

async fn call_llm(config: &LLMConfig, prompt: &str) -> Option<String> {
    let client = reqwest::Client::new();

    let is_anthropic = config.provider == "anthropic";
    let url = if is_anthropic {
        "https://api.anthropic.com/v1/messages"
    } else {
        "https://api.openai.com/v1/chat/completions"
    };

    let body = serde_json::json!({
        "model": config.model,
        "max_tokens": config.max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    });

    let mut builder = client.post(url);

    if is_anthropic {
        builder = builder
            .header("x-api-key", config.api_key.as_str())
            .header("anthropic-version", "2023-06-01")
            .json(&body);
    } else {
        builder = builder
            .bearer_auth(&config.api_key)
            .header("Content-Type", "application/json")
            .json(&body);
    }

    let response = builder.send().await.ok()?;

    if !response.status().is_success() {
        tracing::warn!("LLM API error: {}", response.status());
        return None;
    }

    let text: serde_json::Value = response.json().await.ok()?;

    text.get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .map(String::from)
}
