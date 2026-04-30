//! Twilio API-key verifier.
//!
//! Twilio uses Basic auth with `{AccountSid|ApiKeySid}:AuthToken`. We
//! cannot verify an `SK…` API key without the paired Auth Token, so:
//!
//!   * If a paired `TWILIO_AUTH_TOKEN` / `TWILIO_API_SECRET` is
//!     present in [`VerifierContext::paired_secrets`], Basic-auth as
//!     `<SK_or_AC>:<token>` against
//!     `GET https://api.twilio.com/2010-04-01/Accounts.json` — the
//!     cheapest authenticated endpoint Twilio offers.
//!   * Otherwise return `Unverified`. The pattern still flags the
//!     finding; we just can't roundtrip-confirm it.
//!
//! 200 → verified, 401 → invalid, anything else → unverified.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://api.twilio.com/2010-04-01/Accounts.json";

#[derive(Debug, Default)]
pub struct TwilioVerifier;

#[async_trait]
impl Verifier for TwilioVerifier {
    fn provider(&self) -> &'static str {
        "twilio"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["twilio_key"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let sid = &finding.r#match;
        // Accept either env var name; some users use TWILIO_AUTH_TOKEN
        // (Account SID auth), others TWILIO_API_SECRET (API-key auth).
        let token = ctx
            .paired_secrets
            .get("TWILIO_AUTH_TOKEN")
            .or_else(|| ctx.paired_secrets.get("TWILIO_API_SECRET"));
        let Some(token) = token else {
            return VerificationOutcome::Unverified {
                provider: self.provider().into(),
                reason: "TWILIO_AUTH_TOKEN / TWILIO_API_SECRET not paired".into(),
            };
        };

        let resp = ctx.http.get(URL).basic_auth(sid, Some(token)).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_else(|_| json!({}));
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({
                            "first_page_uri": body.get("first_page_uri").cloned(),
                            "account_count": body
                                .get("accounts")
                                .and_then(|a| a.as_array())
                                .map(Vec::len),
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
    use crate::finding::{Severity, Verdict};
    use std::path::PathBuf;

    fn finding(value: &str) -> Finding {
        Finding {
            path: PathBuf::from("a.rb"),
            line: 1,
            column: 1,
            r#match: value.into(),
            pattern: "twilio_key".into(),
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

    fn ctx_with_token(http: reqwest::Client) -> VerifierContext {
        let mut ctx = VerifierContext {
            http,
            timeout: std::time::Duration::from_secs(5),
            paired_secrets: std::collections::HashMap::new(),
        };
        ctx.paired_secrets
            .insert("TWILIO_AUTH_TOKEN".into(), "tok".into());
        ctx
    }

    /// Custom verify variant that targets a mockito base URL instead of
    /// the hard-coded production URL.
    async fn verify_against(
        base: &str,
        finding: &Finding,
        ctx: &VerifierContext,
    ) -> VerificationOutcome {
        let sid = &finding.r#match;
        let token = ctx
            .paired_secrets
            .get("TWILIO_AUTH_TOKEN")
            .cloned()
            .unwrap_or_default();
        let resp = ctx
            .http
            .get(format!("{base}/2010-04-01/Accounts.json"))
            .basic_auth(sid, Some(&token))
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: "twilio".into(),
                        meta: json!({}),
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: "twilio".into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: "twilio".into(),
                        reason: format!("HTTP {status}"),
                    }
                }
            }
            Err(e) => VerificationOutcome::Unverified {
                provider: "twilio".into(),
                reason: format!("net: {e}"),
            },
        }
    }

    #[tokio::test]
    async fn verifies_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/2010-04-01/Accounts.json")
            .with_status(200)
            .with_body("{\"accounts\":[]}")
            .create_async()
            .await;
        let ctx = ctx_with_token(reqwest::Client::new());
        let out = verify_against(
            &server.url(),
            &finding("SK0123456789abcdef0123456789abcdef"),
            &ctx,
        )
        .await;
        assert!(matches!(out, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn invalid_on_401() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/2010-04-01/Accounts.json")
            .with_status(401)
            .with_body("unauthorized")
            .create_async()
            .await;
        let ctx = ctx_with_token(reqwest::Client::new());
        let out = verify_against(
            &server.url(),
            &finding("SK0123456789abcdef0123456789abcdef"),
            &ctx,
        )
        .await;
        assert!(matches!(
            out,
            VerificationOutcome::Invalid {
                http_status: 401,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn unverified_without_token() {
        let v = TwilioVerifier;
        let ctx = VerifierContext::new(5).expect("ctx");
        let out = v
            .verify(&finding("SK0123456789abcdef0123456789abcdef"), &ctx)
            .await;
        assert!(matches!(out, VerificationOutcome::Unverified { .. }));
    }
}
