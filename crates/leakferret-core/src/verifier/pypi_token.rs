//! `PyPI` upload-token verifier.
//!
//! `PyPI` does not expose a dedicated "is this token alive?" endpoint, so
//! we exploit the upload endpoint's auth-vs-authz split:
//!
//!   * `POST https://upload.pypi.org/legacy/` with Basic
//!     `__token__:<TOKEN>` and an empty body returns:
//!     - **401** if the token is unknown / revoked → `Invalid`
//!     - **403** if the token is known but lacks scope for the implied
//!       project → `Unverified` (token *shape* is valid but we can't
//!       enumerate scope without a project name to try)
//!     - **400** if `PyPI` rejects the empty form before auth-checking →
//!       `Unverified` (we cannot decide). Some `PyPI` deployments do this.
//!     - **200/202** → `Verified` (rare without a real upload).
//!
//! The 403 case is the most common outcome for valid project-scoped
//! tokens, and we surface it as `Unverified` with an explanatory
//! reason rather than `Invalid` to avoid false negatives.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const URL: &str = "https://upload.pypi.org/legacy/";

#[derive(Debug, Default)]
pub struct PyPiTokenVerifier;

#[async_trait]
impl Verifier for PyPiTokenVerifier {
    fn provider(&self) -> &'static str {
        "pypi"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["pypi_token"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let token = &finding.r#match;
        if !token.starts_with("pypi-") {
            return VerificationOutcome::Unverified {
                provider: self.provider().into(),
                reason: "token does not have expected `pypi-` prefix".into(),
            };
        }

        let resp = ctx
            .http
            .post(URL)
            .basic_auth("__token__", Some(token))
            .body("")
            .send()
            .await;

        classify(resp, self.provider())
    }
}

fn classify(
    resp: Result<reqwest::Response, reqwest::Error>,
    provider: &'static str,
) -> VerificationOutcome {
    match resp {
        Ok(r) => {
            let status = r.status();
            let code = status.as_u16();
            if status.is_success() {
                VerificationOutcome::Verified {
                    provider: provider.into(),
                    meta: json!({ "http_status": code }),
                }
            } else if code == 401 {
                VerificationOutcome::Invalid {
                    provider: provider.into(),
                    http_status: code,
                }
            } else if code == 403 {
                VerificationOutcome::Unverified {
                    provider: provider.into(),
                    reason: "token shape valid but cannot enumerate project scope".into(),
                }
            } else {
                VerificationOutcome::Unverified {
                    provider: provider.into(),
                    reason: format!("unexpected HTTP {status}"),
                }
            }
        }
        Err(e) => VerificationOutcome::Unverified {
            provider: provider.into(),
            reason: format!("network: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn verify_against(base: &str, value: &str) -> VerificationOutcome {
        let http = reqwest::Client::new();
        let resp = http
            .post(format!("{base}/legacy/"))
            .basic_auth("__token__", Some(value))
            .body("")
            .send()
            .await;
        classify(resp, "pypi")
    }

    #[tokio::test]
    async fn verifies_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/legacy/")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "pypi-abc").await;
        assert!(matches!(out, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn invalid_on_401() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/legacy/")
            .with_status(401)
            .with_body("nope")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "pypi-abc").await;
        assert!(matches!(
            out,
            VerificationOutcome::Invalid {
                http_status: 401,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn unverified_on_403() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/legacy/")
            .with_status(403)
            .with_body("forbidden")
            .create_async()
            .await;
        let out = verify_against(&server.url(), "pypi-abc").await;
        assert!(matches!(out, VerificationOutcome::Unverified { .. }));
    }
}
