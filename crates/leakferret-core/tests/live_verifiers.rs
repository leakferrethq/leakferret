//! Live verifier smoke tests, gated on environment tokens.
//!
//! Each test is **skipped (passes trivially)** when its token env var is unset,
//! so the normal test suite is unaffected. To actually exercise a verifier
//! against the real provider API, set the env var to a throwaway read-only
//! token and run:
//!
//!   `cargo test -p leakferret-core --test live_verifiers -- --nocapture`
//!
//! or trigger the `live-verifiers` GitHub Actions workflow (which maps repo
//! secrets to these env vars). A `FAIL` means the verifier did not return
//! `Verified` for a token we believe is live — i.e. a wrong endpoint/auth in
//! the verifier, or a dead token.

use std::collections::HashMap;

use leakferret_core::verifier::{
    DatabricksVerifier, FigmaVerifier, GroqVerifier, HuggingFaceVerifier, LinearVerifier,
    NotionVerifier, PostmanVerifier, ReplicateVerifier, ShopifyVerifier, SquareVerifier,
    VerificationOutcome, Verifier, VerifierContext,
};
use leakferret_core::{Finding, Severity, Verdict};

fn finding(pattern: &str, value: &str) -> Finding {
    Finding {
        path: std::path::PathBuf::from("live.env"),
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

async fn check(
    provider: &str,
    env: &str,
    v: &dyn Verifier,
    pattern: &str,
    paired: HashMap<String, String>,
) {
    let Ok(token) = std::env::var(env) else {
        eprintln!("SKIP  {provider}: {env} not set");
        return;
    };
    if token.trim().is_empty() {
        eprintln!("SKIP  {provider}: {env} is empty");
        return;
    }
    let mut ctx = VerifierContext::new(20).expect("verifier context");
    ctx.paired_secrets = paired;
    let f = finding(pattern, token.trim());
    match v.verify(&f, &ctx).await {
        VerificationOutcome::Verified { .. } => println!("PASS  {provider}: verified live"),
        VerificationOutcome::Invalid { http_status, .. } => panic!(
            "FAIL  {provider}: token rejected (HTTP {http_status}). Wrong auth/endpoint, or the token is dead."
        ),
        VerificationOutcome::Unverified { reason, .. } => {
            panic!("FAIL  {provider}: could not verify ({reason}).")
        }
    }
}

macro_rules! live {
    ($name:ident, $provider:literal, $env:literal, $verifier:expr, $pattern:literal) => {
        #[tokio::test]
        async fn $name() {
            check($provider, $env, &$verifier, $pattern, HashMap::new()).await;
        }
    };
}

live!(
    huggingface,
    "huggingface",
    "LEAKFERRET_TEST_HUGGINGFACE_TOKEN",
    HuggingFaceVerifier,
    "huggingface_token"
);
live!(
    groq,
    "groq",
    "LEAKFERRET_TEST_GROQ_TOKEN",
    GroqVerifier,
    "groq_key"
);
live!(
    replicate,
    "replicate",
    "LEAKFERRET_TEST_REPLICATE_TOKEN",
    ReplicateVerifier,
    "replicate_token"
);
live!(
    notion,
    "notion",
    "LEAKFERRET_TEST_NOTION_TOKEN",
    NotionVerifier,
    "notion_token"
);
live!(
    postman,
    "postman",
    "LEAKFERRET_TEST_POSTMAN_TOKEN",
    PostmanVerifier,
    "postman_key"
);
live!(
    figma,
    "figma",
    "LEAKFERRET_TEST_FIGMA_TOKEN",
    FigmaVerifier,
    "figma_token"
);
live!(
    linear,
    "linear",
    "LEAKFERRET_TEST_LINEAR_TOKEN",
    LinearVerifier,
    "linear_key"
);
live!(
    square,
    "square",
    "LEAKFERRET_TEST_SQUARE_TOKEN",
    SquareVerifier,
    "square_token"
);

// Tenant-scoped: also need the host, passed via paired_secrets the same way the
// engine would extract it from context.
#[tokio::test]
async fn shopify() {
    let mut paired = HashMap::new();
    if let Ok(d) = std::env::var("LEAKFERRET_TEST_SHOPIFY_DOMAIN") {
        paired.insert("SHOPIFY_DOMAIN".into(), d.trim().into());
    }
    check(
        "shopify",
        "LEAKFERRET_TEST_SHOPIFY_TOKEN",
        &ShopifyVerifier,
        "shopify_token",
        paired,
    )
    .await;
}

#[tokio::test]
async fn databricks() {
    let mut paired = HashMap::new();
    if let Ok(h) = std::env::var("LEAKFERRET_TEST_DATABRICKS_HOST") {
        paired.insert("DATABRICKS_HOST".into(), h.trim().into());
    }
    check(
        "databricks",
        "LEAKFERRET_TEST_DATABRICKS_TOKEN",
        &DatabricksVerifier,
        "databricks_token",
        paired,
    )
    .await;
}
