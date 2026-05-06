//! Pretty terminal output. Uses [`owo-colors`] which suppresses
//! styling when stdout is not a TTY.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

use owo_colors::OwoColorize;

use crate::finding::{Finding, Severity, Verdict};
use crate::verifier::VerificationOutcome;

use super::Reporter;

#[derive(Debug, Clone, Default)]
pub struct PrettyReporter {
    pub no_color: bool,
}

impl Reporter for PrettyReporter {
    fn emit<W: Write>(&self, findings: &[Finding], out: &mut W) -> io::Result<()> {
        if findings.is_empty() {
            writeln!(out, "  {}", "✔ no candidate secrets found".green().bold())?;
            return Ok(());
        }

        // Group by (commit, path). For working-tree scans `commit` is
        // None and the grouping degenerates to "by path" like before.
        let mut by_group: BTreeMap<(Option<String>, PathBuf), Vec<&Finding>> = BTreeMap::new();
        for f in findings {
            by_group
                .entry((f.git_commit.clone(), f.path.clone()))
                .or_default()
                .push(f);
        }

        for ((commit, path), group) in &by_group {
            // History scans: print commit short-sha + subject above the path.
            if let Some(commit) = commit {
                let short = commit.get(..8).unwrap_or(commit);
                let subject = group
                    .iter()
                    .find_map(|f| f.git_commit_subject.as_deref())
                    .unwrap_or("");
                writeln!(
                    out,
                    "{} {} {}",
                    "commit".dimmed(),
                    short.yellow().bold(),
                    subject.dimmed(),
                )?;
            }
            writeln!(out, "{}", path.display().to_string().cyan().bold())?;
            for f in group {
                let verdict = match f.verdict {
                    Verdict::Real => "REAL".red().bold().to_string(),
                    Verdict::Fixture => "FIXTURE".dimmed().to_string(),
                    Verdict::Unknown => "UNKNOWN".yellow().to_string(),
                };
                let sev = severity_tag(f.severity);
                let conf = f
                    .confidence
                    .map(|c| {
                        #[allow(clippy::cast_possible_truncation)]
                        let pct = (c * 100.0).round() as i32;
                        format!(" ({pct}%)").dimmed().to_string()
                    })
                    .unwrap_or_default();
                let verified_tag = match &f.verification {
                    Some(VerificationOutcome::Verified { provider, .. }) => {
                        format!(
                            " {}{}{}",
                            "[VERIFIED:".green(),
                            provider.green(),
                            "]".green()
                        )
                    }
                    Some(VerificationOutcome::Invalid { provider, .. }) => {
                        format!(
                            " {}{}{}",
                            "[REJECTED:".dimmed(),
                            provider.dimmed(),
                            "]".dimmed()
                        )
                    }
                    _ => String::new(),
                };
                writeln!(
                    out,
                    "  {}  {}{}  {}  {}  {}{}",
                    format_args!("L{}:{}", f.line, f.column)
                        .to_string()
                        .dimmed(),
                    verdict,
                    conf,
                    sev,
                    f.pattern.magenta(),
                    f.redacted_match().dimmed(),
                    verified_tag,
                )?;
                if let Some(reason) = &f.reason {
                    writeln!(out, "    {} {}", "↳".dimmed(), reason.dimmed())?;
                }
                if let Some(rep) = &f.replacement {
                    writeln!(out, "    {} {}", "-".dimmed(), rep.old_line.red())?;
                    writeln!(out, "    {} {}", "+".dimmed(), rep.new_line.green())?;
                }
            }
            writeln!(out)?;
        }

        let total = findings.len();
        let real = findings.iter().filter(|f| f.is_real()).count();
        let unknown = findings
            .iter()
            .filter(|f| matches!(f.verdict, Verdict::Unknown))
            .count();
        let verified = findings.iter().filter(|f| f.is_verified()).count();
        writeln!(
            out,
            "{} findings  ·  {}  ·  {}  ·  {}",
            total,
            format!("{real} real").red().bold(),
            format!("{verified} verified").green().bold(),
            format!("{unknown} unknown").yellow(),
        )?;
        Ok(())
    }
}

fn severity_tag(sev: Severity) -> String {
    match sev {
        Severity::Critical => " CRITICAL ".on_red().white().bold().to_string(),
        Severity::High => " HIGH ".red().to_string(),
        Severity::Medium => " MED ".yellow().to_string(),
        Severity::Low => " LOW ".dimmed().to_string(),
        Severity::Unknown => " ? ".dimmed().to_string(),
    }
}
