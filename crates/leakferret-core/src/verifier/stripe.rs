//! Stripe secret-key verifier. `GET /v1/balance` with Basic auth
//! (`sk_live_…:` as the username, empty password).

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.stripe.com/v1/balance";

#[derive(Debug, Default)]
pub struct StripeVerifier;

#[async_trait]
impl Verifier for StripeVerifier {
    fn provider(&self) -> &'static str {
        "stripe"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["stripe_secret"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .get(URL)
            .basic_auth(&finding.r#match, None::<String>)
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
                            "livemode":  body.get("livemode").cloned(),
                            "currency":  body.get("available")
                                .and_then(|a| a.as_array())
                                .and_then(|a| a.first())
                                .and_then(|b| b.get("currency").cloned()),
                        }),
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
