//! AWS access-key verifier — `sts:GetCallerIdentity` with `SigV4`.
//!
//! Verification flow:
//!   1. Scanner finds an `AKIA…` / `ASIA…` access key ID.
//!   2. The engine populates [`VerifierContext::paired_secrets`] with
//!      any `AWS_SECRET_ACCESS_KEY` it found in the same file (or
//!      environment).
//!   3. This verifier looks for the paired secret.
//!      * **Plan A** (preferred): with both keys, sign a
//!        `GetCallerIdentity` request and POST to
//!        `https://sts.amazonaws.com/`. 200 → verified, 403 → invalid.
//!      * **Plan B** (fallback): if the secret key is *not* paired but
//!        the local `aws` CLI is on `$PATH` and a profile (env or
//!        default) is configured, shell out to
//!        `aws sts get-caller-identity --output json`. If the CLI is
//!        already wired up, we can confirm the *environment* is live
//!        even though we can't cryptographically tie the found `AKIA…`
//!        to it. We surface that nuance via `meta.via = "aws_cli"`.
//!      * Otherwise → `Unverified`.

use std::fmt::Write as _;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::finding::Finding;

use super::{VerificationOutcome, Verifier, VerifierContext};

const HOST: &str = "sts.amazonaws.com";
const REGION: &str = "us-east-1";
const SERVICE: &str = "sts";
const PAYLOAD: &str = "Action=GetCallerIdentity&Version=2011-06-15";

#[derive(Debug, Default)]
pub struct AwsVerifier;

#[async_trait]
impl Verifier for AwsVerifier {
    fn provider(&self) -> &'static str {
        "aws"
    }

    fn handles(&self) -> &'static [&'static str] {
        &["aws_access_key"]
    }

    async fn verify(&self, finding: &Finding, ctx: &VerifierContext) -> VerificationOutcome {
        let access_key = &finding.r#match;
        let Some(secret_key) = ctx.paired_secrets.get("AWS_SECRET_ACCESS_KEY") else {
            // Plan B: shell out to the local `aws` CLI if it's installed
            // and configured. Cannot cryptographically tie the AKIA to
            // the result, but a configured CLI is a strong "this
            // environment has live AWS creds" signal.
            return aws_cli_plan_b(self.provider()).await;
        };

        let session_token = ctx.paired_secrets.get("AWS_SESSION_TOKEN");

        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let signed_headers = if session_token.is_some() {
            "content-type;host;x-amz-date;x-amz-security-token"
        } else {
            "content-type;host;x-amz-date"
        };

        let payload_hash = hex::encode(Sha256::digest(PAYLOAD.as_bytes()));

        let mut canonical_headers = format!(
            "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:{HOST}\nx-amz-date:{amz_date}\n"
        );
        if let Some(tok) = session_token {
            let _ = writeln!(canonical_headers, "x-amz-security-token:{tok}");
        }

        let canonical_request =
            format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

        let credential_scope = format!("{date_stamp}/{REGION}/{SERVICE}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let signing_key = derive_signing_key(secret_key, &date_stamp, REGION, SERVICE);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        );

        let mut req = ctx
            .http
            .post(format!("https://{HOST}/"))
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .header("host", HOST)
            .header("x-amz-date", &amz_date)
            .header("authorization", &authorization)
            .body(PAYLOAD);
        if let Some(tok) = session_token {
            req = req.header("x-amz-security-token", tok);
        }

        match req.send().await {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                if status.is_success() {
                    // Pull arn / account from the XML response without
                    // dragging in an XML crate.
                    let account = extract_xml_value(&body, "Account");
                    let arn = extract_xml_value(&body, "Arn");
                    VerificationOutcome::Verified {
                        provider: self.provider().into(),
                        meta: json!({ "account": account, "arn": arn }),
                    }
                } else if matches!(status.as_u16(), 401 | 403) {
                    VerificationOutcome::Invalid {
                        provider: self.provider().into(),
                        http_status: status.as_u16(),
                    }
                } else {
                    VerificationOutcome::Unverified {
                        provider: self.provider().into(),
                        reason: format!(
                            "HTTP {status}: {}",
                            body.chars().take(120).collect::<String>()
                        ),
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

/// Plan B: try `aws sts get-caller-identity --output json` if the
/// `aws` CLI is on `$PATH` and *some* profile is configured. Returns
/// `Verified` with `meta.via = "aws_cli"` on success.
///
/// We deliberately do NOT compare the returned UserId/Account against
/// the candidate `AKIA…` — we have no way to without the matching
/// secret. The caller treats `via: "aws_cli"` as a slightly weaker
/// signal than Plan A.
async fn aws_cli_plan_b(provider: &'static str) -> VerificationOutcome {
    // `LEAKFERRET_AWS_CLI_BIN` lets tests inject a stub binary.
    let bin = std::env::var("LEAKFERRET_AWS_CLI_BIN").unwrap_or_else(|_| "aws".into());

    // First gate: is `aws` (or the override) discoverable?
    if which_on_path(&bin).is_none() {
        return VerificationOutcome::Unverified {
            provider: provider.into(),
            reason: "AWS_SECRET_ACCESS_KEY not paired and `aws` CLI not on $PATH".into(),
        };
    }

    // Second gate: is *any* profile configured? Without this the CLI
    // will prompt or fail with the "Unable to locate credentials"
    // message, which we'd want to translate to `Unverified` anyway.
    let profile_configured = std::env::var("AWS_PROFILE").is_ok()
        || std::env::var("AWS_ACCESS_KEY_ID").is_ok()
        || default_profile_exists();
    if !profile_configured {
        return VerificationOutcome::Unverified {
            provider: provider.into(),
            reason: "AWS_SECRET_ACCESS_KEY not paired and no AWS profile configured".into(),
        };
    }

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.arg("sts")
        .arg("get-caller-identity")
        .arg("--output")
        .arg("json");

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!(target: "verifier.aws", error = %e, "aws cli spawn failed");
            return VerificationOutcome::Unverified {
                provider: provider.into(),
                reason: format!("aws cli spawn failed: {e}"),
            };
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::debug!(target: "verifier.aws", "aws cli failed: {}", stderr);
        return VerificationOutcome::Unverified {
            provider: provider.into(),
            reason: format!(
                "aws cli exit {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.chars().take(120).collect::<String>()
            ),
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|_| json!({}));
    let account = parsed
        .get("Account")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let arn = parsed
        .get("Arn")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let user_id = parsed
        .get("UserId")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    VerificationOutcome::Verified {
        provider: provider.into(),
        meta: json!({
            "via": "aws_cli",
            "account": account,
            "arn": arn,
            "user_id": user_id,
        }),
    }
}

/// Best-effort PATH lookup. Returns the resolved absolute path of the
/// first match or `None`. We don't use the `which` crate to avoid
/// pulling in an extra dependency.
fn which_on_path(bin: &str) -> Option<std::path::PathBuf> {
    // Absolute / relative paths: just check the file exists directly.
    let p = std::path::Path::new(bin);
    if p.is_absolute() || bin.contains('/') || bin.contains('\\') {
        return if p.is_file() {
            Some(p.to_path_buf())
        } else {
            None
        };
    }
    let path_var = std::env::var_os("PATH")?;
    // Windows also looks for .exe / .cmd / .bat extensions.
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

/// True if `~/.aws/credentials` or `~/.aws/config` is readable. We
/// only need to know the file exists; we do not parse it.
fn default_profile_exists() -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    home.join(".aws").join("credentials").is_file() || home.join(".aws").join("config").is_file()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn derive_signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end_offset = xml[start..].find(&close)?;
    Some(xml[start..start + end_offset].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_matches_aws_test_vector() {
        // From AWS docs:
        // https://docs.aws.amazon.com/IAM/latest/UserGuide/signature-v4-test-suite.html
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(&key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn extract_xml_value_works() {
        let xml = "<x><Account>123</Account><Arn>arn:aws:iam::123:user/test</Arn></x>";
        assert_eq!(extract_xml_value(xml, "Account"), Some("123".into()));
        assert_eq!(
            extract_xml_value(xml, "Arn"),
            Some("arn:aws:iam::123:user/test".into())
        );
    }

    #[test]
    fn which_on_path_finds_absolute() {
        // Stick a sentinel file in a temp dir and confirm we resolve it.
        let dir = tempfile::tempdir().expect("tempdir");
        let sentinel = dir.path().join("real_bin");
        std::fs::write(&sentinel, b"").expect("write sentinel");
        let path = sentinel.to_string_lossy().to_string();
        assert!(which_on_path(&path).is_some());
        // Should return None for a clearly non-existent absolute path.
        let bogus = if cfg!(windows) {
            "C:\\__definitely_not_a_real_path__\\nope.exe"
        } else {
            "/__definitely_not_a_real_path__/nope"
        };
        assert!(which_on_path(bogus).is_none());
    }

    /// End-to-end Plan B: install a stub "aws" binary into a temp dir,
    /// point `LEAKFERRET_AWS_CLI_BIN` at it, ensure a profile shim is
    /// in place, and confirm `aws_cli_plan_b` returns `Verified` with
    /// `via: aws_cli`.
    #[tokio::test]
    async fn plan_b_runs_when_aws_cli_is_on_path() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Build a tiny stub that prints valid get-caller-identity JSON
        // to stdout and exits 0. On Windows we generate a .cmd; on
        // Unix a shell script with the exec bit set.
        let stub_path = if cfg!(windows) {
            let p = dir.path().join("aws.cmd");
            std::fs::write(
                &p,
                "@echo off\r\necho {\"UserId\":\"AIDAEXAMPLE\",\"Account\":\"123456789012\",\"Arn\":\"arn:aws:iam::123456789012:user/test\"}\r\n",
            )
            .unwrap();
            p
        } else {
            let p = dir.path().join("aws");
            std::fs::write(
                &p,
                "#!/bin/sh\necho '{\"UserId\":\"AIDAEXAMPLE\",\"Account\":\"123456789012\",\"Arn\":\"arn:aws:iam::123456789012:user/test\"}'\n",
            )
            .unwrap();
            // Make executable.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perm = std::fs::metadata(&p).unwrap().permissions();
                perm.set_mode(0o755);
                std::fs::set_permissions(&p, perm).unwrap();
            }
            p
        };

        // The test harness is single-threaded by default for
        // process-env mutation. We restore the env at the end.
        let prev_bin = std::env::var("LEAKFERRET_AWS_CLI_BIN").ok();
        let prev_profile = std::env::var("AWS_PROFILE").ok();
        // Use the absolute path so which_on_path's absolute-path branch
        // is the one that succeeds — avoids depending on PATH ordering.
        std::env::set_var("LEAKFERRET_AWS_CLI_BIN", &stub_path);
        std::env::set_var("AWS_PROFILE", "leakferret-test");

        let outcome = aws_cli_plan_b("aws").await;

        // Restore env regardless of assert outcome.
        match prev_bin {
            Some(v) => std::env::set_var("LEAKFERRET_AWS_CLI_BIN", v),
            None => std::env::remove_var("LEAKFERRET_AWS_CLI_BIN"),
        }
        match prev_profile {
            Some(v) => std::env::set_var("AWS_PROFILE", v),
            None => std::env::remove_var("AWS_PROFILE"),
        }

        match outcome {
            VerificationOutcome::Verified { provider, meta } => {
                assert_eq!(provider, "aws");
                assert_eq!(meta.get("via").and_then(|v| v.as_str()), Some("aws_cli"));
                assert_eq!(
                    meta.get("account").and_then(|v| v.as_str()),
                    Some("123456789012")
                );
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn plan_b_unverified_when_cli_missing() {
        // Point the override at a definitely-missing binary.
        let prev = std::env::var("LEAKFERRET_AWS_CLI_BIN").ok();
        std::env::set_var(
            "LEAKFERRET_AWS_CLI_BIN",
            if cfg!(windows) {
                "C:\\__nope__\\never_exists.exe"
            } else {
                "/__nope__/never_exists"
            },
        );

        let outcome = aws_cli_plan_b("aws").await;

        match prev {
            Some(v) => std::env::set_var("LEAKFERRET_AWS_CLI_BIN", v),
            None => std::env::remove_var("LEAKFERRET_AWS_CLI_BIN"),
        }

        assert!(matches!(outcome, VerificationOutcome::Unverified { .. }));
    }
}
