//! GitHub PAT / fine-grained PAT verifier.
//!
//! Uses `GET https://api.github.com/user` with the token as the
//! Authorization Bearer. 200 → verified, 401 → invalid.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.github.com/user";

#[derive(Debug, Default)]
pub struct GitHubVerifier;

#[async_trait]
impl Verifier for GitHubVerifier {
    fn provider(&self) -> &'static str {
        "github"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["github_token", "github_fine_grained"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let token = &finding.r#match;
        let resp = ctx
            .http
            .get(URL)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(token)
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
                            "login": body.get("login").cloned(),
                            "id":    body.get("id").cloned(),
                            "type":  body.get("type").cloned(),
                        }),
                    }
                } else if status.as_u16() == 401 || status.as_u16() == 403 {
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
