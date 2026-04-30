//! Datadog API-key verifier.
//!
//! Datadog exposes a dedicated key-introspection endpoint:
//! `GET https://api.datadoghq.com/api/v1/validate` returns
//! `{ "valid": true }` when the `DD-API-KEY` header is good, 403 when
//! it isn't. No billing impact, no scope requirement.
//!
//! Note: the bare-32-hex pattern (`[a-f0-9]{32}`) is extremely generic
//! and would false-positive on any md5 hash, so the pattern that feeds
//! this verifier is anchored on a `dd_api_key=` / `datadog_api_key:`
//! style context (see `patterns/registry.rs`).

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.datadoghq.com/api/v1/validate";

#[derive(Debug, Default)]
pub struct DatadogVerifier;

#[async_trait]
impl Verifier for DatadogVerifier {
    fn provider(&self) -> &'static str {
        "datadog"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["datadog_api_key"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx
            .http
            .get(URL)
            .header("DD-API-KEY", &finding.r#match)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    let valid = body
                        .get("valid")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    if valid {
                        VerificationOutcome::Verified {
                            provider: self.provider().into(),
                            meta: json!({ "valid": true }),
                        }
                    } else {
                        VerificationOutcome::Invalid {
                            provider: self.provider().into(),
                            http_status: status.as_u16(),
                        }
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
            .get(format!("{base}/api/v1/validate"))
            .header("DD-API-KEY", value)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    let valid = body
                        .get("valid")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    if valid {
                        VerificationOutcome::Verified {
                            provider: "datadog".into(),
                            meta: json!({}),
                        }
                    } else {
                        VerificationOutcome::Invalid {
                            provider: "datadog".into(),
                            http_status: status.as_u16(),
                        }
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: "datadog".into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: "datadog".into(),
                        reason: format!("HTTP {status}"),
                    }
                }
            }
            Err(e) => VerificationOutcome::Unverified {
                provider: "datadog".into(),
                reason: format!("net: {e}"),
            },
        }
    }

    #[tokio::test]
    async fn verifies_on_valid_true() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/validate")
            .with_status(200)
            .with_body("{\"valid\":true}")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "deadbeef").await;
        assert!(matches!(out, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn invalid_on_403() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/validate")
            .with_status(403)
            .with_body("forbidden")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "deadbeef").await;
        assert!(matches!(
            out,
            VerificationOutcome::Invalid {
                http_status: 403,
                ..
            }
        ));
    }
}
