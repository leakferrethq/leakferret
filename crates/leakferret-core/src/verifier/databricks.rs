//! Databricks token verifier. Tenant-scoped: it needs the workspace host, which
//! the engine extracts from the finding's context into paired_secrets as
//! `DATABRICKS_HOST`. `GET https://{host}/api/2.0/clusters/list` with a Bearer
//! token. Untested live — confirm with a real key.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

#[derive(Debug, Default)]
pub struct DatabricksVerifier;

#[async_trait]
impl Verifier for DatabricksVerifier {
    fn provider(&self) -> &'static str {
        "databricks"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["databricks_token"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let Some(host) = ctx.paired_secrets.get("DATABRICKS_HOST") else {
            return VerificationOutcome::Unverified {
                provider: self.provider().into(),
                reason: "workspace host (*.databricks.com / *.azuredatabricks.net) not found near the token".into(),
            };
        };
        let url = format!("https://{host}/api/2.0/clusters/list");
        let resp = ctx
            .http
            .get(&url)
            .bearer_auth(&finding.r#match)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({ "host": host }),
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
