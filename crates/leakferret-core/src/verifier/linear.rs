//! Linear API-key verifier. GraphQL `{ viewer { id } }` with the raw key in
//! the `Authorization` header (Linear personal API keys are sent bare, not as
//! a Bearer token). A bad key returns HTTP 400 from the GraphQL endpoint.
//! Untested against a live key — confirm with a real token before trusting.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.linear.app/graphql";
const QUERY: &str = r#"{"query":"{ viewer { id } }"}"#;

#[derive(Debug, Default)]
pub struct LinearVerifier;

#[async_trait]
impl Verifier for LinearVerifier {
    fn provider(&self) -> &'static str {
        "linear"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["linear_key"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .post(URL)
            .header("Authorization", &finding.r#match)
            .header("Content-Type", "application/json")
            .body(QUERY)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({}),
                    }
                } else if matches!(status.as_u16(), 400 | 401 | 403) {
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
