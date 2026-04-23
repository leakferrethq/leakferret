//! Host-LLM prompt template + structured candidate payload.
//!
//! The MCP server, the VS Code extension, and the Claude Code skill
//! all consume this payload. The host's own LLM does the
//! classification reasoning — we never make an LLM HTTP call from
//! the engine.

use serde::{Deserialize, Serialize};

use crate::finding::{Finding, FindingView};

/// The system prompt sent to the host model. Stable wording — changes
/// here are observable from MCP `prompts/get` and will affect the
/// host model's verdict distribution.
pub const SYSTEM_PROMPT: &str = r#"You're reviewing regex hits that may be hardcoded secrets in source code.
For each candidate you'll get: the file path, the pattern name, a redacted
preview of the matched value (first 4 and last 4 chars only), and ~7 lines
of surrounding context.

Classify each candidate as one of:
  REAL    - looks like a live secret that shipped in production source
  FIXTURE - looks like a test fixture, mock, stub, example, doc, or
            obvious dummy value (sk_test_xxx, AKIAIOSFODNN7EXAMPLE,
            redacted/placeholder strings, etc.)
  UNKNOWN - can't tell from this context alone

Bias toward FIXTURE when the path contains spec/, test/, tests/,
fixtures/, examples/, docs/, demo/, sample/, mock/, dummy/, or
filenames like .env.example / .env.sample.

Bias toward REAL when the path is under app/, lib/, src/, config/
(excluding config/credentials.yml.enc which is already encrypted),
cmd/, or services/, AND the matched value has live provider structure.

Default to UNKNOWN when there's genuine ambiguity. Don't guess.

Output strict JSON only, no prose:
[{"id": "...", "verdict": "REAL|FIXTURE|UNKNOWN", "reason": "...", "confidence": 0.0-1.0}, ...]"#;

/// Candidate as exposed to the host model (no raw secret value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPromptCandidate {
    pub id: String,
    pub path: String,
    pub pattern: String,
    pub severity: String,
    pub match_redacted: String,
    pub context: Vec<String>,
}

/// Full payload to feed the host model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPrompt {
    pub system: &'static str,
    pub candidates: Vec<HostPromptCandidate>,
}

impl HostPrompt {
    pub fn for_findings(findings: &[Finding]) -> Self {
        Self {
            system: SYSTEM_PROMPT,
            candidates: findings
                .iter()
                .enumerate()
                .map(|(idx, f)| {
                    let view: FindingView = f.into();
                    let redacted = view.match_redacted.clone();
                    HostPromptCandidate {
                        id: idx.to_string(),
                        path: view.path.to_string_lossy().into_owned(),
                        pattern: view.pattern,
                        severity: view.severity.to_string(),
                        match_redacted: view.match_redacted,
                        // Redact the secret inside the context lines too —
                        // the host model only needs the surrounding shape,
                        // not the raw value.
                        context: f
                            .context
                            .iter()
                            .map(|l| l.replace(&f.r#match, &redacted))
                            .collect(),
                    }
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, Verdict};
    use std::path::PathBuf;

    #[test]
    fn prompt_excludes_raw_match() {
        // Use a value that does NOT appear in SYSTEM_PROMPT (which cites
        // AKIAIOSFODNN7EXAMPLE as a fixture example), and plant it in a
        // context line so we exercise context redaction too.
        let secret = "AKIAREALLEAKSECRET99";
        let f = Finding {
            path: PathBuf::from("a.rb"),
            line: 1,
            column: 1,
            r#match: secret.into(),
            pattern: "aws_access_key".into(),
            severity: Severity::High,
            context: vec![format!("KEY = '{secret}'")],
            verdict: Verdict::Unknown,
            reason: None,
            confidence: None,
            verification: None,
            fingerprint: None,
            replacement: None,
            git_commit: None,
            git_commit_subject: None,
        };
        let prompt = HostPrompt::for_findings(&[f]);
        let json = serde_json::to_string(&prompt).unwrap();
        assert!(!json.contains(secret));
        assert!(json.contains("AKIA...ET99"));
    }
}
