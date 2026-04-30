//! Mailgun API-key verifier.
//!
//! Basic-auths as `api:<KEY>` against
//! `GET https://api.mailgun.net/v3/domains` — the cheapest authenticated
//! endpoint. Returns 200 with a paginated domain list when the key is
//! valid, 401 when it isn't.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.mailgun.net/v3/domains";

#[derive(Debug, Default)]
pub struct MailgunVerifier;

#[async_trait]
impl Verifier for MailgunVerifier {
    fn provider(&self) -> &'static str {
        "mailgun"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["mailgun_key"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .get(URL)
            .basic_auth("api", Some(&finding.r#match))
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    let total = body.get("total_count").cloned();
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({ "domain_count": total }),
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
            .get(format!("{base}/v3/domains"))
            .basic_auth("api", Some(value))
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: "mailgun".into(),
                        meta: json!({}),
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: "mailgun".into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: "mailgun".into(),
                        reason: format!("HTTP {status}"),
                    }
                }
            }
            Err(e) => VerificationOutcome::Unverified {
                provider: "mailgun".into(),
                reason: format!("net: {e}"),
            },
        }
    }

    #[tokio::test]
    async fn verifies_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/v3/domains")
            .with_status(200)
            .with_body("{\"total_count\":1,\"items\":[]}")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "key-abc").await;
        assert!(matches!(out, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn invalid_on_401() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/v3/domains")
            .with_status(401)
            .with_body("nope")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "key-abc").await;
        assert!(matches!(
            out,
            VerificationOutcome::Invalid {
                http_status: 401,
                ..
            }
        ));
    }
}
