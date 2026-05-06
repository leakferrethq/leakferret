//! SARIF 2.1.0 reporter. Output is consumable by GitHub Code Scanning,
//! Azure DevOps, and most enterprise SAST aggregators.

use std::io::{self, Write};

use serde_json::{json, Value};

use crate::finding::{Finding, Severity, Verdict};
use crate::patterns::PatternRegistry;

use super::Reporter;

#[derive(Debug, Clone, Copy, Default)]
pub struct SarifReporter;

impl SarifReporter {
    fn rules() -> Vec<Value> {
        PatternRegistry::builtin()
            .iter()
            .map(|p| {
                json!({
                    "id":   p.id,
                    "name": p.id,
                    "shortDescription": { "text": p.description },
                    "defaultConfiguration": {
                        "level": severity_level(p.severity, None),
                    },
                })
            })
            .collect()
    }
}

impl Reporter for SarifReporter {
    fn emit<W: Write>(&self, findings: &[Finding], out: &mut W) -> io::Result<()> {
        let results: Vec<Value> = findings
            .iter()
            .map(|f| {
                json!({
                    "ruleId": f.pattern,
                    "level":  severity_level(f.severity, Some(f.verdict)),
                    "message": {
                        "text": format!("{}: {} ({})", f.pattern, f.redacted_match(), f.verdict)
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": f.path.display().to_string() },
                            "region": {
                                "startLine":   f.line,
                                "startColumn": f.column,
                            },
                        }
                    }],
                    "properties": {
                        "verdict":      f.verdict.to_string(),
                        "confidence":   f.confidence,
                        "verified":     f.is_verified(),
                        "provider":     f.verification.as_ref().map(|v| v.provider().to_string()),
                        "fingerprint":  f.fingerprint.as_ref().map(super::super::finding::fingerprint::Fingerprint::as_str),
                        "git_commit":         f.git_commit,
                        "git_commit_subject": f.git_commit_subject,
                    },
                })
            })
            .collect();

        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name":           crate::NAME,
                        "version":        crate::VERSION,
                        "informationUri": "https://github.com/leakferrethq/leakferret",
                        "rules":          Self::rules(),
                    }
                },
                "results": results,
            }]
        });
        serde_json::to_writer_pretty(&mut *out, &sarif)?;
        writeln!(out)
    }
}

fn severity_level(sev: Severity, verdict: Option<Verdict>) -> &'static str {
    if matches!(verdict, Some(Verdict::Fixture)) {
        return "note";
    }
    if matches!(verdict, Some(Verdict::Unknown)) {
        return "warning";
    }
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    }
}
