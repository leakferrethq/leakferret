//! Square access-token verifier. `GET /v2/locations` with a Bearer token.
//! Untested against a live key — confirm with a real token before trusting.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://connect.squareup.com/v2/locations";
const SQUARE_VERSION: &str = "2024-06-04";

#[derive(Debug, Default)]
pub struct SquareVerifier;

#[async_trait]
impl Verifier for SquareVerifier {
    fn provider(&self) -> &'static str {
        "square"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["square_token"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .get(URL)
            .bearer_auth(&finding.r#match)
            .header("Square-Version", SQUARE_VERSION)
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
