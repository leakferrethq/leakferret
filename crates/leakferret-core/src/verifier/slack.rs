//! Slack bot / user-token verifier. `POST https://slack.com/api/auth.test`
//! returns 200 with `ok: true|false`.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://slack.com/api/auth.test";

#[derive(Debug, Default)]
pub struct SlackVerifier;

#[async_trait]
impl Verifier for SlackVerifier {
    fn provider(&self) -> &'static str {
        "slack"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["slack_token"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .post(URL)
            .bearer_auth(&finding.r#match)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if !status.is_success() {
                    return VerificationOutcome::Unverified {
                        provider: self.provider().into(),
                        reason: format!("HTTP {status}"),
                    };
                }
                let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                let ok = body
                    .get("ok")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                if ok {
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({
                            "team":    body.get("team").cloned(),
                            "user":    body.get("user").cloned(),
                            "team_id": body.get("team_id").cloned(),
                        }),
                    }
                } else {
                    VerificationOutcome::Invalid {
                        provider: self.provider().into(),
                        http_status: 200,
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
