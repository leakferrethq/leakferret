//! Provider verification — the trufflehog-parity feature.
//!
//! A verifier takes a candidate `Finding`, performs a provider-side
//! call that uses the candidate value as the auth header, and returns
//! an [`VerificationOutcome`] reflecting the provider's response.
//!
//! The secret value goes from the user's machine **directly to the
//! provider**. We never proxy or store it. That preserves the privacy
//! pitch even with verification turned on.

mod anthropic;
mod aws;
mod datadog;
mod digitalocean;
mod github;
mod gitlab;
mod heroku;
mod mailgun;
mod npm_token;
mod openai;
mod pypi_token;
mod sendgrid;
mod slack;
mod stripe;
mod trufflehog;
mod twilio;

// Token-only verifiers (fixed-host whoami endpoints).
mod figma;
mod groq;
mod huggingface;
mod linear;
mod notion;
mod postman;
mod replicate;
mod square;

// Tenant-scoped verifiers (host pulled from the finding's context).
mod databricks;
mod shopify;

pub use anthropic::AnthropicVerifier;
pub use aws::AwsVerifier;
pub use datadog::DatadogVerifier;
pub use digitalocean::DigitalOceanVerifier;
pub use github::GitHubVerifier;
pub use gitlab::GitLabVerifier;
pub use heroku::HerokuVerifier;
pub use mailgun::MailgunVerifier;
pub use npm_token::NpmTokenVerifier;
pub use openai::OpenAiVerifier;
pub use pypi_token::PyPiTokenVerifier;
pub use sendgrid::SendGridVerifier;
pub use slack::SlackVerifier;
pub use stripe::StripeVerifier;
pub use trufflehog::TrufflehogVerifier;
pub use twilio::TwilioVerifier;

pub use figma::FigmaVerifier;
pub use groq::GroqVerifier;
pub use huggingface::HuggingFaceVerifier;
pub use linear::LinearVerifier;
pub use notion::NotionVerifier;
pub use postman::PostmanVerifier;
pub use replicate::ReplicateVerifier;
pub use square::SquareVerifier;

pub use databricks::DatabricksVerifier;
pub use shopify::ShopifyVerifier;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// Outcome of a single verification attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Provider returned a success response — key is live.
    Verified {
        provider: String,
        /// Any extra metadata the provider returned (account id, login,
        /// scopes, etc) — never sensitive.
        meta: serde_json::Value,
    },
    /// Provider explicitly rejected the credentials (401/403). The
    /// key is not currently active (rotated, malformed, or never real).
    Invalid { provider: String, http_status: u16 },
    /// Verifier could not run for non-credential reasons (network
    /// failure, rate-limit, paired-secret missing, etc).
    Unverified { provider: String, reason: String },
}

impl VerificationOutcome {
    pub fn provider(&self) -> &str {
        match self {
            Self::Verified { provider, .. }
            | Self::Invalid { provider, .. }
            | Self::Unverified { provider, .. } => provider,
        }
    }

    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid { .. })
    }

    /// Signal strength, used to pick the best outcome across the verifiers
    /// that handle one finding: a confirmed result beats a definitive
    /// rejection, which beats an inconclusive one. This stops an absent
    /// fallback (trufflehog not installed → `Unverified`) from erasing a
    /// native verifier's verdict.
    fn priority(&self) -> u8 {
        match self {
            Self::Verified { .. } => 3,
            Self::Invalid { .. } => 2,
            Self::Unverified { .. } => 1,
        }
    }
}

/// Implemented per provider.
#[async_trait]
pub trait Verifier: Send + Sync + std::fmt::Debug {
    /// Stable lowercase provider name — `"aws"`, `"github"`, ...
    fn provider(&self) -> &'static str;
    /// Pattern IDs this verifier knows how to handle.
    fn handles(&self) -> &'static [&'static str];
    /// Verify a single finding.
    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome;
}

/// Per-run context made available to every verifier: an HTTP client,
/// timeout, optional environment-paired secrets (e.g. `AWS_SECRET_KEY`
/// from the same file), and tracing.
#[derive(Debug, Clone)]
pub struct VerifierContext {
    pub http: reqwest::Client,
    pub timeout: Duration,
    /// Extra in-process key/value secrets passed by the engine
    /// (paired secret keys discovered nearby, etc).
    pub paired_secrets: HashMap<String, String>,
}

impl VerifierContext {
    pub fn new(timeout_secs: u64) -> crate::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent(format!("leakferret/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| crate::Error::Http {
                provider: "<init>",
                source: e,
            })?;
        Ok(Self {
            http,
            timeout: Duration::from_secs(timeout_secs),
            paired_secrets: HashMap::new(),
        })
    }
}

/// Registry of all verifiers. Resolves `pattern_id` → applicable
/// verifiers, runs them concurrently with bounded parallelism.
#[derive(Debug, Default)]
pub struct VerifierRegistry {
    by_pattern: HashMap<&'static str, Vec<Arc<dyn Verifier>>>,
    all: Vec<Arc<dyn Verifier>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Built-in registry with every shipped verifier registered.
    ///
    /// Provider-native verifiers are registered **first** so they win
    /// per-pattern resolution; the trufflehog binary wrap is registered
    /// **last** as a fallback safety net for every pattern we don't
    /// natively verify.
    pub fn builtin() -> Self {
        let mut r = Self::new();
        // Native verifiers first.
        r.register(Arc::new(GitHubVerifier));
        r.register(Arc::new(GitLabVerifier));
        r.register(Arc::new(StripeVerifier));
        r.register(Arc::new(OpenAiVerifier));
        r.register(Arc::new(AnthropicVerifier));
        r.register(Arc::new(SlackVerifier));
        r.register(Arc::new(AwsVerifier));
        r.register(Arc::new(TwilioVerifier));
        r.register(Arc::new(SendGridVerifier));
        r.register(Arc::new(MailgunVerifier));
        r.register(Arc::new(DatadogVerifier));
        r.register(Arc::new(HerokuVerifier));
        r.register(Arc::new(NpmTokenVerifier));
        r.register(Arc::new(PyPiTokenVerifier));
        r.register(Arc::new(DigitalOceanVerifier));
        // Token-only verifiers (fixed-host whoami endpoints). Live-untested;
        // confirm each with a real key before relying on its verdict.
        r.register(Arc::new(HuggingFaceVerifier));
        r.register(Arc::new(SquareVerifier));
        r.register(Arc::new(LinearVerifier));
        r.register(Arc::new(NotionVerifier));
        r.register(Arc::new(PostmanVerifier));
        r.register(Arc::new(FigmaVerifier));
        r.register(Arc::new(ReplicateVerifier));
        r.register(Arc::new(GroqVerifier));
        // Tenant-scoped: verify only when the host is found in context.
        r.register(Arc::new(ShopifyVerifier));
        r.register(Arc::new(DatabricksVerifier));
        // Credibility-borrow fallback — must be last so it never
        // out-races a provider-native verifier for the same pattern.
        r.register(Arc::new(TrufflehogVerifier));
        r
    }

    pub fn register(&mut self, v: Arc<dyn Verifier>) {
        for &p in v.handles() {
            self.by_pattern.entry(p).or_default().push(Arc::clone(&v));
        }
        self.all.push(v);
    }

    pub fn for_pattern(&self, pattern_id: &str) -> &[Arc<dyn Verifier>] {
        self.by_pattern
            .get(pattern_id)
            .map_or(&[][..], Vec::as_slice)
    }

    pub fn all(&self) -> &[Arc<dyn Verifier>] {
        &self.all
    }

    /// Verify a slice of findings with bounded concurrency. Writes
    /// the result to `finding.verification`. Findings without a
    /// matching verifier are left untouched.
    pub async fn verify_all(
        &self,
        findings: &mut [Finding],
        ctx: &VerifierContext,
        concurrency: usize,
    ) {
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        let mut next = 0usize;

        loop {
            while in_flight.len() < concurrency && next < findings.len() {
                let idx = next;
                next += 1;
                let pattern = findings[idx].pattern.clone();
                let verifiers = self.for_pattern(&pattern).to_vec();
                if verifiers.is_empty() {
                    continue;
                }
                let finding_snapshot = findings[idx].clone();
                let ctx = ctx.clone();
                in_flight.push(async move {
                    // Keep the strongest signal across verifiers (see
                    // `VerificationOutcome::priority`).
                    let mut best: Option<VerificationOutcome> = None;
                    for v in &verifiers {
                        let outcome = v.verify(&finding_snapshot, &ctx).await;
                        if best
                            .as_ref()
                            .is_none_or(|b| outcome.priority() >= b.priority())
                        {
                            best = Some(outcome);
                        }
                        if best.as_ref().is_some_and(VerificationOutcome::is_verified) {
                            break;
                        }
                    }
                    (idx, best)
                });
            }

            match in_flight.next().await {
                Some((idx, Some(outcome))) => {
                    findings[idx].verification = Some(outcome);
                }
                Some((_, None)) => {}
                None => break,
            }
            if next >= findings.len() && in_flight.is_empty() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, Verdict};
    use std::path::PathBuf;

    fn finding(pattern: &str, value: &str) -> Finding {
        Finding {
            path: PathBuf::from("a.rb"),
            line: 1,
            column: 1,
            r#match: value.into(),
            pattern: pattern.into(),
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

    #[test]
    fn registry_resolves_by_pattern() {
        let r = VerifierRegistry::builtin();
        assert!(!r.for_pattern("github_token").is_empty());
        assert!(!r.for_pattern("stripe_secret").is_empty());
        assert!(r.for_pattern("nonexistent").is_empty());
        // Token-only verifiers added on top of the trufflehog fallback.
        for id in [
            "huggingface_token",
            "square_token",
            "linear_key",
            "notion_token",
            "postman_key",
            "figma_token",
            "replicate_token",
            "groq_key",
            "shopify_token",
            "databricks_token",
        ] {
            assert!(
                r.for_pattern(id).len() >= 2,
                "{id} should resolve to a native verifier + trufflehog fallback"
            );
        }
    }

    #[tokio::test]
    async fn verify_all_skips_when_no_verifier_handles() {
        let r = VerifierRegistry::new();
        let ctx = VerifierContext::new(5).unwrap();
        let mut fs = vec![finding("nonexistent", "x")];
        r.verify_all(&mut fs, &ctx, 4).await;
        assert!(fs[0].verification.is_none());
    }
}
