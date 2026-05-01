//! `DigitalOcean` personal-access-token verifier.
//!
//! `GET https://api.digitalocean.com/v2/account` with a Bearer token
//! returns the account profile when the PAT is valid, 401 when it
//! isn't. Cheapest authenticated endpoint, no scope requirement.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.digitalocean.com/v2/account";

#[derive(Debug, Default)]
pub struct DigitalOceanVerifier;

#[async_trait]
impl Verifier for DigitalOceanVerifier {
    fn provider(&self) -> &'static str {
        "digitalocean"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["digitalocean_pat"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx.http.get(URL).bearer_auth(&finding.r#match).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    let account = body.get("account").cloned().unwrap_or_else(|| json!({}));
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({
                            "uuid":  account.get("uuid").cloned(),
                            "email": account.get("email").cloned(),
                            "team":  account.get("team").cloned(),
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
            .get(format!("{base}/v2/account"))
            .bearer_auth(value)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: "digitalocean".into(),
                        meta: json!({}),
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: "digitalocean".into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: "digitalocean".into(),
                        reason: format!("HTTP {status}"),
                    }
                }
            }
            Err(e) => VerificationOutcome::Unverified {
                provider: "digitalocean".into(),
                reason: format!("net: {e}"),
            },
        }
    }

    #[tokio::test]
    async fn verifies_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/v2/account")
            .with_status(200)
            .with_body("{\"account\":{\"uuid\":\"u\",\"email\":\"a@b.c\"}}")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "dop_v1_x").await;
        assert!(matches!(out, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn invalid_on_401() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/v2/account")
            .with_status(401)
            .with_body("nope")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "dop_v1_x").await;
        assert!(matches!(
            out,
            VerificationOutcome::Invalid {
                http_status: 401,
                ..
            }
        ));
    }
}
