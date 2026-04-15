//! The [`Finding`] is the unit of work that flows through every stage
//! of the engine: scanner emits it, classifier writes its verdict,
//! verifier marks it verified-or-not, rewriter attaches a replacement,
//! reporter renders it.
//!
//! Every output path uses [`Finding::redacted_match`] — first-4 +
//! last-4 chars only. The full secret never enters a serialised
//! buffer.

pub mod fingerprint;
mod severity;
mod verdict;

pub use fingerprint::Fingerprint;
pub use severity::Severity;
pub use verdict::Verdict;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::rewriter::Replacement;
use crate::verifier::VerificationOutcome;

/// One candidate secret in a file. Mutable by design — each pipeline
/// stage writes a different sub-region of the struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Path relative to the scan root.
    pub path: PathBuf,
    /// 1-indexed line number.
    pub line: usize,
    /// 1-indexed column number where the match starts.
    pub column: usize,
    /// The full captured secret value. **Never** include this in
    /// reports or network calls — go through [`Self::redacted_match`].
    #[serde(skip_serializing)]
    pub r#match: String,
    /// Pattern ID that produced this match.
    pub pattern: String,
    /// Pre-classifier severity from the pattern definition.
    pub severity: Severity,
    /// Lines of context around the match (no trailing newlines). Skipped
    /// in serialization: the line holding the secret would otherwise leak
    /// the raw value into any whole-`Finding` / `ScanReport` buffer. The
    /// classifier prompt redacts it separately before it reaches a model.
    #[serde(skip_serializing)]
    pub context: Vec<String>,
    /// Verdict set by the classifier; `Unknown` until classified.
    pub verdict: Verdict,
    /// Human-readable classifier explanation.
    pub reason: Option<String>,
    /// Classifier confidence in [0, 1].
    pub confidence: Option<f32>,
    /// Verifier outcome (None = verifier not run).
    pub verification: Option<VerificationOutcome>,
    /// HMAC-fingerprint used by baseline lookups.
    pub fingerprint: Option<Fingerprint>,
    /// Rewriter proposal for `Real` findings.
    pub replacement: Option<Replacement>,
    /// Git commit SHA the finding came from (only set by the git-history
    /// scanner; `None` for working-tree scans).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    /// Git commit subject line (first line of the commit message).
    /// Only populated together with `git_commit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit_subject: Option<String>,
}

impl Finding {
    /// First 4 + last 4 chars, separated by `...`. Returned as-is if
    /// the secret is shorter than 12 chars (no useful redaction).
    pub fn redacted_match(&self) -> String {
        if self.r#match.chars().count() < 12 {
            return self.r#match.clone();
        }
        let chars: Vec<char> = self.r#match.chars().collect();
        let head: String = chars.iter().take(4).collect();
        let tail: String = chars
            .iter()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{head}...{tail}")
    }

    /// Stable cache key used by the proxy and MCP layers to skip
    /// re-classification of unchanged candidates across runs. SHA-256
    /// over the bits the LLM sees: pattern + redacted match + context.
    pub fn cache_key(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.pattern.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.redacted_match().as_bytes());
        hasher.update(b"\0");
        for line in &self.context {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        hex::encode(hasher.finalize())
    }

    /// True if classified as `Real`.
    pub fn is_real(&self) -> bool {
        matches!(self.verdict, Verdict::Real)
    }

    /// True if classified as `Fixture`.
    pub fn is_fixture(&self) -> bool {
        matches!(self.verdict, Verdict::Fixture)
    }

    /// True if verifier confirmed the secret is live.
    pub fn is_verified(&self) -> bool {
        matches!(
            self.verification,
            Some(VerificationOutcome::Verified { .. })
        )
    }
}

/// Serialisation-safe projection used by JSON / SARIF reporters and
/// the MCP server response. Strips the raw match value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingView {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub pattern: String,
    pub severity: Severity,
    pub match_redacted: String,
    pub verdict: Verdict,
    pub reason: Option<String>,
    pub confidence: Option<f32>,
    pub fingerprint: Option<Fingerprint>,
    pub verification: Option<VerificationOutcome>,
    /// Git commit SHA (only set when the finding originated from a
    /// git-history scan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    /// Subject line of the originating commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit_subject: Option<String>,
}

impl From<&Finding> for FindingView {
    fn from(f: &Finding) -> Self {
        Self {
            path: f.path.clone(),
            line: f.line,
            column: f.column,
            pattern: f.pattern.clone(),
            severity: f.severity,
            match_redacted: f.redacted_match(),
            verdict: f.verdict,
            reason: f.reason.clone(),
            confidence: f.confidence,
            fingerprint: f.fingerprint.clone(),
            verification: f.verification.clone(),
            git_commit: f.git_commit.clone(),
            git_commit_subject: f.git_commit_subject.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(match_value: &str) -> Finding {
        Finding {
            path: PathBuf::from("app/config.rb"),
            line: 12,
            column: 3,
            r#match: match_value.to_string(),
            pattern: "aws_access_key".to_string(),
            severity: Severity::High,
            context: vec!["AKIA = '...'".to_string()],
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
    fn redacts_long_secrets_to_first4_dots_last4() {
        let f = sample_finding("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(f.redacted_match(), "AKIA...MPLE");
    }

    #[test]
    fn keeps_short_secrets_intact_for_redaction() {
        let f = sample_finding("short");
        assert_eq!(f.redacted_match(), "short");
    }

    #[test]
    fn cache_key_is_stable_over_identical_inputs() {
        let a = sample_finding("AKIAIOSFODNN7EXAMPLE");
        let b = sample_finding("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn cache_key_differs_with_pattern() {
        let mut a = sample_finding("AKIAIOSFODNN7EXAMPLE");
        let mut b = sample_finding("AKIAIOSFODNN7EXAMPLE");
        a.pattern = "p1".into();
        b.pattern = "p2".into();
        assert_ne!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn finding_view_strips_raw_match() {
        let f = sample_finding("AKIAIOSFODNN7EXAMPLE");
        let view = FindingView::from(&f);
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(json.contains("AKIA...MPLE"));
    }
}
