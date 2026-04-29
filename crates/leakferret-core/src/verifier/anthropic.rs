//! Anthropic API-key verifier. `GET /v1/models` with `x-api-key`.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.anthropic.com/v1/models";
const ANTHROPIC_VERSION: &str = "2023-06-01";

#[derive(Debug, Default)]
pub struct AnthropicVerifier;

#[async_trait]
impl Verifier for AnthropicVerifier {
    fn provider(&self) -> &'static str {
        "anthropic"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["anthropic_key"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .get(URL)
            .header("x-api-key", &finding.r#match)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    let model_count = body
                        .get("data")
                        .and_then(|d| d.as_array())
                        .map_or(0, Vec::len);
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({ "model_count": model_count }),
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: self.provider().into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: self.provider().into(),
                        reason: format!("unexpected HTTP {status}"),
                    }
                }
            }
            Err(e) => VerificationOutcome::Unverified {
                provider: self.provider().into(),
                reason: format!("network: {e}"),
            },
        }
    }
}
