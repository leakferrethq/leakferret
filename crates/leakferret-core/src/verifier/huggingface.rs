//! Hugging Face token verifier. `GET /api/whoami-v2` with a Bearer token.
//! Untested against a live key — confirm with a real token before trusting.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://huggingface.co/api/whoami-v2";

#[derive(Debug, Default)]
pub struct HuggingFaceVerifier;

#[async_trait]
impl Verifier for HuggingFaceVerifier {
    fn provider(&self) -> &'static str {
        "huggingface"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["huggingface_token"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx.http.get(URL).bearer_auth(&finding.r#match).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({}),
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
