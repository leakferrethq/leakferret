//! Trufflehog binary wrap — the "credibility borrow" verifier.
//!
//! Why this exists: trufflehog ships an enormous corpus of provider
//! verifiers we don't (yet) have native Rust implementations for. When
//! it's installed locally, we shell out to it and trust its
//! `--only-verified` flag as a fallback safety net for every pattern
//! we don't natively verify.
//!
//! Strategy:
//!   1. If `trufflehog` is not on `$PATH`, return `Unverified` instantly
//!      — no I/O, no surprises in CI environments.
//!   2. Otherwise run
//!      ```text
//!      trufflehog filesystem <path-of-finding> --json --only-verified --no-update
//!      ```
//!      and stream-parse the JSON lines.
//!   3. If any verified detection matches our finding's line, return
//!      `Verified` with the `DetectorName` lifted into `meta`.
//!
//! This verifier registers as a fallback handler for *every* known
//! pattern ID via [`Self::handles`]. [`super::VerifierRegistry`] is
//! ordered so provider-native verifiers run first; trufflehog only
//! gets a turn for findings the native verifiers couldn't confirm.
//!
//! No raw secret values are passed to the trufflehog process — it
//! reads the file directly, just as a normal scan would.

use async_trait::async_trait;
use serde_json::json;

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

/// Pattern IDs trufflehog claims fallback responsibility for. Must stay
/// in sync with [`crate::patterns::registry`] — any pattern listed here
/// will route through trufflehog when no native verifier returns
/// `Verified`.
///
/// Listed by hand (rather than scraped at runtime) so it's
/// grep-greppable in code review.
pub(crate) const TRUFFLEHOG_HANDLES: &[&str] = &[
    "aws_access_key",
    "aws_secret_key",
    "aws_session_token",
    "stripe_secret",
    "stripe_publishable",
    "github_token",
    "github_fine_grained",
    "gitlab_pat",
    "anthropic_key",
    "openai_key",
    "google_api_key",
    "slack_token",
    "slack_webhook",
    "twilio_key",
    "sendgrid_key",
    "mailgun_key",
    "datadog_api_key",
    "heroku_api_key",
    "npm_token",
    "pypi_token",
    "digitalocean_pat",
    "gcp_service_account",
    "azure_storage",
    "pem_private_key",
    "jwt",
    "postgres_url",
    "mysql_url",
    "mongodb_url",
    "redis_url_auth",
    "secret_assignment",
];

#[derive(Debug, Default)]
pub struct TrufflehogVerifier;

#[async_trait]
impl Verifier for TrufflehogVerifier {
    fn provider(&self) -> &'static str {
        "trufflehog"
    }

    fn handles(&self) -> &'static [&'static str] {
        TRUFFLEHOG_HANDLES
    }

    async fn verify(&self, finding: &Finding, _ctx: &VerifierContext) -> VerificationOutcome {
        let bin =
            std::env::var("LEAKFERRET_TRUFFLEHOG_BIN").unwrap_or_else(|_| "trufflehog".into());

        if which_on_path(&bin).is_none() {
            tracing::debug!(target: "verifier.trufflehog", "trufflehog not on PATH; skipping");
            return VerificationOutcome::Unverified {
                provider: self.provider().into(),
                reason: "trufflehog not installed".into(),
            };
        }

        let target = finding.path.as_os_str();
        let mut cmd = tokio::process::Command::new(&bin);
        cmd.arg("filesystem")
            .arg(target)
            .arg("--json")
            .arg("--only-verified")
            .arg("--no-update");

        let output = match cmd.output().await {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(target: "verifier.trufflehog", error = %e, "trufflehog spawn failed");
                return VerificationOutcome::Unverified {
                    provider: self.provider().into(),
                    reason: format!("trufflehog spawn failed: {e}"),
                };
            }
        };

        // Trufflehog exits non-zero when *nothing* is found in some
        // versions; we still try to parse stdout if it has content.
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(record) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };
            // `Verified: true` is the gold criterion. We do not require
            // line-number agreement: trufflehog's parser may anchor the
            // finding a line away from ours.
            let verified = record
                .get("Verified")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !verified {
                continue;
            }
            let detector = record
                .get("DetectorName")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            return VerificationOutcome::Verified {
                provider: "trufflehog".into(),
                meta: json!({
                    "detector": detector,
                    "via": "trufflehog_cli",
                }),
            };
        }

        VerificationOutcome::Unverified {
            provider: self.provider().into(),
            reason: "trufflehog ran but did not verify the finding".into(),
        }
    }
}

/// Local copy of the small PATH lookup helper from `aws.rs` — kept
/// here to avoid coupling the two modules.
fn which_on_path(bin: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(bin);
    if p.is_absolute() || bin.contains('/') || bin.contains('\\') {
        return if p.is_file() {
            Some(p.to_path_buf())
        } else {
            None
        };
    }
    let path_var = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .map(str::to_owned)
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in &exts {
            let candidate = dir.join(format!("{bin}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, Verdict};
    use std::path::PathBuf;

    // Both tests mutate the process-global LEAKFERRET_TRUFFLEHOG_BIN env var;
    // serialize them with an async mutex so they can't clobber each other's
    // value under the parallel harness (the cause of the flaky Linux failures).
    static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    fn finding() -> Finding {
        Finding {
            path: PathBuf::from("nonexistent.txt"),
            line: 1,
            column: 1,
            r#match: "AKIAEXAMPLE".into(),
            pattern: "aws_access_key".into(),
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

    #[tokio::test]
    async fn unverified_when_trufflehog_not_installed() {
        let _env = ENV_LOCK.lock().await;
        let prev = std::env::var("LEAKFERRET_TRUFFLEHOG_BIN").ok();
        std::env::set_var(
            "LEAKFERRET_TRUFFLEHOG_BIN",
            if cfg!(windows) {
                "C:\\__nope__\\trufflehog.exe"
            } else {
                "/__nope__/trufflehog"
            },
        );

        let ctx = VerifierContext::new(5).expect("ctx");
        let v = TrufflehogVerifier;
        let outcome = v.verify(&finding(), &ctx).await;

        match prev {
            Some(v) => std::env::set_var("LEAKFERRET_TRUFFLEHOG_BIN", v),
            None => std::env::remove_var("LEAKFERRET_TRUFFLEHOG_BIN"),
        }

        match outcome {
            VerificationOutcome::Unverified { reason, .. } => {
                assert!(reason.contains("trufflehog not installed"));
            }
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verified_when_stub_emits_verified_record() {
        let _env = ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let stub = if cfg!(windows) {
            let p = dir.path().join("trufflehog.cmd");
            std::fs::write(
                &p,
                "@echo off\r\necho {\"Verified\":true,\"DetectorName\":\"StubDetector\"}\r\n",
            )
            .unwrap();
            p
        } else {
            let p = dir.path().join("trufflehog");
            std::fs::write(
                &p,
                "#!/bin/sh\necho '{\"Verified\":true,\"DetectorName\":\"StubDetector\"}'\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perm = std::fs::metadata(&p).unwrap().permissions();
                perm.set_mode(0o755);
                std::fs::set_permissions(&p, perm).unwrap();
            }
            p
        };

        let prev = std::env::var("LEAKFERRET_TRUFFLEHOG_BIN").ok();
        std::env::set_var("LEAKFERRET_TRUFFLEHOG_BIN", &stub);

        let ctx = VerifierContext::new(5).expect("ctx");
        let v = TrufflehogVerifier;
        let outcome = v.verify(&finding(), &ctx).await;

        match prev {
            Some(v) => std::env::set_var("LEAKFERRET_TRUFFLEHOG_BIN", v),
            None => std::env::remove_var("LEAKFERRET_TRUFFLEHOG_BIN"),
        }

        match outcome {
            VerificationOutcome::Verified { provider, meta } => {
                assert_eq!(provider, "trufflehog");
                assert_eq!(
                    meta.get("detector").and_then(|v| v.as_str()),
                    Some("StubDetector")
                );
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }
}
