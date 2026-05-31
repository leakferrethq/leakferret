//! Proposes a code edit that swaps a hardcoded secret for an env-var
//! lookup in whichever language the file is written in, plus a
//! `.env.example` entry and optional secret-manager seeding commands.
//!
//! We never read or store the secret value. The seeding commands are
//! emitted with placeholder text the developer fills in locally; the
//! actual value is supplied to Vault / Doppler / AWS SM by the
//! developer directly.

mod language;
mod proposal;

pub use language::Language;
pub use proposal::Replacement;

use regex::Regex;

use crate::config::RewriteBackend;
use crate::finding::{Finding, Verdict};

/// Stateless rewriter — operates on a single finding at a time.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rewriter {
    pub backend: RewriteBackend,
}

impl Rewriter {
    pub fn new(backend: RewriteBackend) -> Self {
        Self { backend }
    }

    /// Propose a replacement. Returns `None` if the finding isn't
    /// classified `Real`, the language isn't supported, or the secret
    /// doesn't appear in the captured context (e.g. it spans multiple
    /// lines).
    pub fn propose(self, finding: &Finding) -> Option<Replacement> {
        // Real always; Unknown when the caller opted in via the engine
        // (the engine decides *which* findings reach this, so we accept
        // both verdicts and reject only the clearly-not-a-secret ones).
        if !matches!(finding.verdict, Verdict::Real | Verdict::Unknown) {
            return None;
        }
        let lang = Language::detect(&finding.path)?;
        if !lang.is_supported() {
            return None;
        }

        let middle = finding.context.len() / 2;
        let source_line = finding.context.get(middle).cloned().unwrap_or_default();
        if source_line.is_empty() {
            return None;
        }

        let env_var = derive_env_var_name(&source_line, &finding.pattern);
        let call = lang.env_call(&env_var)?;
        let new_line = rewrite_line(&source_line, &finding.r#match, &call)?;
        if new_line == source_line {
            return None;
        }

        // old_line is informational only: apply/dry-run-diff rewrite the
        // real file via finding.r#match, never this field. Redact the
        // secret here so it stays out of serialized output and the diff.
        let old_line = source_line.replace(&finding.r#match, &finding.redacted_match());

        Some(Replacement {
            env_var: env_var.clone(),
            language: lang,
            old_line,
            new_line,
            env_example_line: format!("{env_var}="),
            seed_commands: seed_commands(self.backend, &env_var),
        })
    }
}

fn rewrite_line(line: &str, secret: &str, call: &str) -> Option<String> {
    if !line.contains(secret) {
        return None;
    }
    // Prefer replacing the quoted form so the surrounding quotes are
    // consumed. The regex crate has no backreferences, so match each
    // quote character explicitly rather than with a `\1` backref.
    for quote in ['\'', '"'] {
        let quoted = format!("{quote}{secret}{quote}");
        if line.contains(&quoted) {
            return Some(line.replacen(&quoted, call, 1));
        }
    }
    Some(line.replacen(secret, call, 1))
}

fn derive_env_var_name(line: &str, pattern_id: &str) -> String {
    // 1) SHOUTY_SNAKE constant on LHS.
    if let Some(caps) = Regex::new(r"\b([A-Z][A-Z0-9_]+)\s*[:=]")
        .unwrap()
        .captures(line)
    {
        return sanitise(&caps[1]);
    }
    // 2) snake_case var on LHS → upper.
    if let Some(caps) = Regex::new(r"\b([a-z_][a-z0-9_]*)\s*[:=]")
        .unwrap()
        .captures(line)
    {
        return sanitise(&caps[1].to_ascii_uppercase());
    }
    // 3) camelCase hash key → SNAKE_CASE.
    if let Some(caps) = Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*:")
        .unwrap()
        .captures(line)
    {
        let camel = &caps[1];
        let snake: String = camel
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if c.is_ascii_uppercase() && i > 0 {
                    vec!['_', c]
                } else {
                    vec![c]
                }
            })
            .collect::<String>()
            .to_ascii_uppercase();
        return sanitise(&snake);
    }
    sanitise(&pattern_id.to_ascii_uppercase())
}

fn sanitise(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    cleaned.trim_matches('_').to_string()
}

fn seed_commands(backend: RewriteBackend, env_var: &str) -> Vec<String> {
    let placeholder = format!("<paste-{}-value-here>", env_var.to_ascii_lowercase());
    let mut cmds = vec![format!(
        "# Pick one — leakferret never stores or transmits the actual value:"
    )];
    match backend {
        RewriteBackend::Env => {
            cmds.push(format!("export {env_var}={placeholder}"));
        }
        RewriteBackend::Vault => {
            cmds.push(format!("vault kv put secret/app {env_var}={placeholder}"));
        }
        RewriteBackend::Doppler => {
            cmds.push(format!("doppler secrets set {env_var}={placeholder}"));
        }
        RewriteBackend::AwsSecretsManager => {
            let sm_id = env_var.to_ascii_lowercase().replace('_', "-");
            cmds.push(format!(
                "aws secretsmanager put-secret-value --secret-id {sm_id} --secret-string \"{placeholder}\""
            ));
        }
        RewriteBackend::Infisical => {
            cmds.push(format!("infisical secrets set {env_var}={placeholder}"));
        }
    }
    cmds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::path::PathBuf;

    fn real_finding(path: &str, ctx_line: &str, value: &str) -> Finding {
        Finding {
            path: PathBuf::from(path),
            line: 2,
            column: 1,
            r#match: value.into(),
            pattern: "aws_access_key".into(),
            severity: Severity::High,
            context: vec!["# header".into(), ctx_line.into(), "# footer".into()],
            verdict: Verdict::Real,
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
    fn rewrites_ruby_constant() {
        let f = real_finding(
            "app/config.rb",
            "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            "AKIAIOSFODNN7EXAMPLE",
        );
        let r = Rewriter::default().propose(&f).unwrap();
        assert_eq!(r.env_var, "AWS_ACCESS_KEY");
        assert_eq!(r.new_line, "AWS_ACCESS_KEY = ENV.fetch('AWS_ACCESS_KEY')");
        // `old_line` keeps the line for the diff but redacts the secret.
        assert_eq!(r.old_line, "AWS_ACCESS_KEY = 'AKIA...MPLE'");
        assert!(!r.old_line.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn rewrites_python_dict() {
        let f = real_finding(
            "app/config.py",
            "API_KEY = \"AKIAIOSFODNN7EXAMPLE\"",
            "AKIAIOSFODNN7EXAMPLE",
        );
        let r = Rewriter::default().propose(&f).unwrap();
        assert!(r.new_line.contains("os.environ"));
    }

    #[test]
    fn returns_none_for_non_real() {
        let mut f = real_finding(
            "app/config.rb",
            "X = 'AKIAIOSFODNN7EXAMPLE'",
            "AKIAIOSFODNN7EXAMPLE",
        );
        f.verdict = Verdict::Fixture;
        assert!(Rewriter::default().propose(&f).is_none());
    }
}
