//! npm registry token verifier.
//!
//! `GET https://registry.npmjs.org/-/whoami` returns the logged-in
//! username when the bearer token is valid, 401 when it's not. No cost,
//! no scope requirement.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://registry.npmjs.org/-/whoami";

#[derive(Debug, Default)]
pub struct NpmTokenVerifier;

#[async_trait]
impl Verifier for NpmTokenVerifier {
    fn provider(&self) -> &'static str {
        "npm"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["npm_token"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx.http.get(URL).bearer_auth(&finding.r#match).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({
                            "username": body.get("username").cloned(),
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
            .get(format!("{base}/-/whoami"))
            .bearer_auth(value)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: "npm".into(),
                        meta: json!({}),
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: "npm".into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: "npm".into(),
                        reason: format!("HTTP {status}"),
                    }
                }
            }
            Err(e) => VerificationOutcome::Unverified {
                provider: "npm".into(),
                reason: format!("net: {e}"),
            },
        }
    }

    #[tokio::test]
    async fn verifies_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/-/whoami")
            .with_status(200)
            .with_body("{\"username\":\"alice\"}")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").await;
        assert!(matches!(out, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn invalid_on_401() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/-/whoami")
            .with_status(401)
            .with_body("nope")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "npm_xxxx").await;
        assert!(matches!(
            out,
            VerificationOutcome::Invalid {
                http_status: 401,
                ..
            }
        ));
    }
}
