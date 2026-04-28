//! GitLab PAT verifier. `GET /api/v4/user` with PRIVATE-TOKEN header.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://gitlab.com/api/v4/user";

#[derive(Debug, Default)]
pub struct GitLabVerifier;

#[async_trait]
impl Verifier for GitLabVerifier {
    fn provider(&self) -> &'static str {
        "gitlab"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["gitlab_pat"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .get(URL)
            .header("PRIVATE-TOKEN", &finding.r#match)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({
                            "username": body.get("username").cloned(),
                            "id":       body.get("id").cloned(),
                        }),
                    }
                } else if status.as_u16() == 401 {
                    VerificationOutcome::Invalid {
                        provider: self.provider().into(),
                        http_status: 401,
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
