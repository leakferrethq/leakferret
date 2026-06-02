//! Shopify access-token verifier. Tenant-scoped: it needs the shop domain,
//! which the engine extracts from the finding's context into paired_secrets as
//! `SHOPIFY_DOMAIN`. `GET https://{shop}/admin/api/2024-04/shop.json` with the
//! `X-Shopify-Access-Token` header. Untested live — confirm with a real key.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

#[derive(Debug, Default)]
pub struct ShopifyVerifier;

#[async_trait]
impl Verifier for ShopifyVerifier {
    fn provider(&self) -> &'static str {
        "shopify"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["shopify_token"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let Some(shop) = ctx.paired_secrets.get("SHOPIFY_DOMAIN") else {
            return VerificationOutcome::Unverified {
                provider: self.provider().into(),
                reason: "shop domain (*.myshopify.com) not found near the token".into(),
            };
        };
        let url = format!("https://{shop}/admin/api/2024-04/shop.json");
        let resp = ctx
            .http
            .get(&url)
            .header("X-Shopify-Access-Token", &finding.r#match)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({ "shop": shop }),
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
