//! Heroku API-key verifier.
//!
//! `GET https://api.heroku.com/account` with a `Bearer` token returns
//! the account profile when the key is valid, 401 when it isn't.
//! Heroku requires the platform API version header
//! (`Accept: application/vnd.heroku+json; version=3`).

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.heroku.com/account";
const ACCEPT: &str = "application/vnd.heroku+json; version=3";

#[derive(Debug, Default)]
pub struct HerokuVerifier;

#[async_trait]
impl Verifier for HerokuVerifier {
    fn provider(&self) -> &'static str {
        "heroku"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["heroku_api_key"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .get(URL)
            .header("Accept", ACCEPT)
            .bearer_auth(&finding.r#match)
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
                            "id":    body.get("id").cloned(),
                            "email": body.get("email").cloned(),
                            "name":  body.get("name").cloned(),
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn verify_against(base: &str, value: &str) -> VerificationOutcome {
        let http = reqwest::Client::new();
        let resp = http
            .get(format!("{base}/account"))
            .header("Accept", ACCEPT)
            .bearer_auth(value)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: "heroku".into(),
                        meta: json!({}),
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: "heroku".into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: "heroku".into(),
                        reason: format!("HTTP {status}"),
                    }
                }
            }
            Err(e) => VerificationOutcome::Unverified {
                provider: "heroku".into(),
                reason: format!("net: {e}"),
            },
        }
    }

    #[tokio::test]
    async fn verifies_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/account")
            .with_status(200)
            .with_body("{\"id\":\"abc\",\"email\":\"u@e.com\"}")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "HRKU-x").await;
        assert!(matches!(out, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn invalid_on_401() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/account")
            .with_status(401)
            .with_body("nope")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "HRKU-x").await;
        assert!(matches!(
            out,
            VerificationOutcome::Invalid {
                http_status: 401,
                ..
            }
        ));
    }
}
