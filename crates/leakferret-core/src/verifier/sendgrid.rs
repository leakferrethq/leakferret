//! `SendGrid` API-key verifier.
//!
//! `GET https://api.sendgrid.com/v3/scopes` is the cheapest reliably
//! authenticated endpoint — it returns the list of scopes granted to
//! the bearer token and has no per-call billing. 200 → verified, 401 →
//! invalid.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.sendgrid.com/v3/scopes";

#[derive(Debug, Default)]
pub struct SendGridVerifier;

#[async_trait]
impl Verifier for SendGridVerifier {
    fn provider(&self) -> &'static str {
        "sendgrid"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["sendgrid_key"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let resp = ctx.http.get(URL).bearer_auth(&finding.r#match).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    let scope_count = body
                        .get("scopes")
                        .and_then(|s| s.as_array())
                        .map_or(0, Vec::len);
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({ "scope_count": scope_count }),
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
    use crate::finding::{Severity, Verdict};
    use std::path::PathBuf;

    fn finding(value: &str) -> Finding {
        Finding {
            path: PathBuf::from("a.rb"),
            line: 1,
            column: 1,
            r#match: value.into(),
            pattern: "sendgrid_key".into(),
            severity: Severity::High,
            context: vec![],
            verdict: Verdict::Unknown,
            reason: None,
            confidence: None,
            verification: None,
            fingerprint: None,
            replacement: None,
            git_commit: None,
            git_commit_subject: None,
        }
    }

    async fn verify_against(base: &str, value: &str) -> VerificationOutcome {
        let http = reqwest::Client::new();
        let resp = http
            .get(format!("{base}/v3/scopes"))
            .bearer_auth(value)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: "sendgrid".into(),
                        meta: json!({}),
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: "sendgrid".into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: "sendgrid".into(),
                        reason: format!("HTTP {status}"),
                    }
                }
            }
            Err(e) => VerificationOutcome::Unverified {
                provider: "sendgrid".into(),
                reason: format!("net: {e}"),
            },
        }
    }

    #[tokio::test]
    async fn verifies_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/v3/scopes")
            .with_status(200)
            .with_body("{\"scopes\":[\"mail.send\"]}")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "SG.x.y").await;
        assert!(matches!(out, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn invalid_on_401() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/v3/scopes")
            .with_status(401)
            .with_body("nope")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "SG.x.y").await;
        assert!(matches!(
            out,
            VerificationOutcome::Invalid {
                http_status: 401,
                ..
            }
        ));
    }

    #[test]
    fn handles_returns_sendgrid_key() {
        assert_eq!(SendGridVerifier.handles(), &["sendgrid_key"]);
        let _ = finding("x");
    }
}
