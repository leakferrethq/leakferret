//! Reporters render `Finding`s for human terminals (pretty), CI
//! pipelines (SARIF), and machine consumers (JSON). All three reuse
//! [`FindingView`](crate::finding::FindingView) which strips the raw
//! match value automatically.

mod json;
mod pretty;
mod sarif;

pub use json::JsonReporter;
pub use pretty::PrettyReporter;
pub use sarif::SarifReporter;

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// User-selectable output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReporterFormat {
    #[default]
    Pretty,
    Json,
    Sarif,
}

impl ReporterFormat {
    // Returns Option (not a FromStr Result) for unknown formats by design.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pretty" => Some(Self::Pretty),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            _ => None,
        }
    }
}

/// Implementations write directly to a `Write` sink.
pub trait Reporter {
    fn emit<W: Write>(&self, findings: &[Finding], out: &mut W) -> io::Result<()>;
}

/// Convenience dispatcher.
pub fn emit<W: Write>(
    format: ReporterFormat,
    findings: &[Finding],
    out: &mut W,
    show_fixtures: bool,
) -> io::Result<()> {
    let filtered: Vec<&Finding> = if show_fixtures {
        findings.iter().collect()
    } else {
        findings.iter().filter(|f| !f.is_fixture()).collect()
    };
    let owned: Vec<Finding> = filtered.into_iter().cloned().collect();

    match format {
        ReporterFormat::Pretty => PrettyReporter::default().emit(&owned, out),
        ReporterFormat::Json => JsonReporter.emit(&owned, out),
        ReporterFormat::Sarif => SarifReporter.emit(&owned, out),
    }
}

/// Exit-code helper. 0 if no `Real` findings; 1 otherwise.
pub fn exit_code(findings: &[Finding]) -> i32 {
    i32::from(findings.iter().any(Finding::is_real))
}
