//! Classifier — assigns a [`Verdict`] (`Real` / `Fixture` / `Unknown`)
//! to each `Finding`.
//!
//! Three modes:
//!
//! * **Offline** — pure heuristics over path, dummy markers, and
//!   pattern severity. No network, no LLM. Cheap and reliable for
//!   obvious cases.
//! * **Host LLM** — engine emits a prompt + structured candidate list
//!   for the host environment's LLM (Claude Code, Cursor, VS Code
//!   `lm.sendRequest`, MCP host model). The host calls the model, we
//!   parse the structured response back through
//!   [`Classifier::apply_verdicts`]. This module does NOT call any
//!   LLM directly — that's the whole point of the MCP-first pivot.
//! * **API proxy** — optional paid tier that posts batches to our
//!   hosted classifier (out of scope for v1 core; the CLI wires it).

mod offline;
mod prompt;

pub use offline::OfflineClassifier;
pub use prompt::{HostPrompt, HostPromptCandidate, SYSTEM_PROMPT};

use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Verdict};

/// User-selectable classification strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClassifyMode {
    #[default]
    Offline,
    HostLlm,
    Api,
}

/// Pluggable classifier. Implementations live in submodules and in
/// downstream crates.
pub trait Classifier: Send + Sync {
    fn classify(&self, findings: &mut [Finding]);
}

/// Parse and apply a host-LLM JSON response to the findings list. The
/// response shape mirrors what the system prompt asks for:
///
/// ```json
/// [{"id":"0","verdict":"REAL","reason":"...","confidence":0.91}]
/// ```
pub fn apply_verdicts(findings: &mut [Finding], response: &str) -> crate::Result<()> {
    #[derive(Deserialize)]
    struct VerdictResp {
        id: String,
        verdict: String,
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        confidence: Option<f32>,
    }

    let parsed: Vec<VerdictResp> = serde_json::from_str(response.trim())?;
    for v in parsed {
        let Ok(idx) = v.id.parse::<usize>() else {
            continue;
        };
        let Some(f) = findings.get_mut(idx) else {
            continue;
        };
        f.verdict = Verdict::parse_loose(&v.verdict);
        f.reason = v.reason;
        f.confidence = v.confidence;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::path::PathBuf;

    fn finding() -> Finding {
        Finding {
            path: PathBuf::from("app/x.rb"),
            line: 1,
            column: 1,
            r#match: "AKIAIOSFODNN7EXAMPLE".into(),
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

    #[test]
    fn apply_verdicts_parses_host_response() {
        let mut fs = vec![finding(), finding()];
        let resp = r#"[{"id":"0","verdict":"REAL","reason":"in app/","confidence":0.9},
                      {"id":"1","verdict":"FIXTURE","reason":"docs"}]"#;
        apply_verdicts(&mut fs, resp).unwrap();
        assert_eq!(fs[0].verdict, Verdict::Real);
        assert_eq!(fs[1].verdict, Verdict::Fixture);
        assert_eq!(fs[0].confidence, Some(0.9));
    }
}
