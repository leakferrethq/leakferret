//! Compiled pattern registry. `RegexSet` does the fast pre-filter
//! ("is *any* pattern matching this line?") and individual `Regex`es
//! do the per-pattern capture when the set says yes.

use regex::{Regex, RegexSet};

use crate::finding::Severity;
use crate::Error;

use super::Pattern;

/// Compiled, queryable registry of all known patterns.
#[derive(Debug)]
pub struct PatternRegistry {
    patterns: Vec<Pattern>,
    set: RegexSet,
    compiled: Vec<Regex>,
}

impl PatternRegistry {
    /// Build a registry from raw `Pattern` definitions.
    pub fn new(patterns: Vec<Pattern>) -> crate::Result<Self> {
        let sources: Vec<&str> = patterns.iter().map(|p| p.regex.as_str()).collect();
        let set = RegexSet::new(&sources).map_err(|e| Error::Pattern {
            name: "<set>".into(),
            source: e,
        })?;
        let compiled = patterns
            .iter()
            .map(|p| {
                Regex::new(&p.regex).map_err(|e| Error::Pattern {
                    name: p.id.clone(),
                    source: e,
                })
            })
            .collect::<crate::Result<Vec<_>>>()?;
        Ok(Self {
            patterns,
            set,
            compiled,
        })
    }

    /// Built-in registry. Mirrors the Ruby `Patterns::DEFINITIONS` list
    /// from the legacy gem (see `legacy-ruby/lib/leakferret/patterns.rb`).
    pub fn builtin() -> Self {
        Self::new(builtin_patterns()).expect("builtin patterns must compile")
    }

    /// Returns indexes of patterns that match the given line, or empty
    /// if none.
    pub fn matches(&self, line: &str) -> Vec<usize> {
        self.set.matches(line).into_iter().collect()
    }

    /// Returns the pattern + compiled regex for an index returned by
    /// [`Self::matches`].
    pub fn get(&self, idx: usize) -> Option<(&Pattern, &Regex)> {
        Some((self.patterns.get(idx)?, self.compiled.get(idx)?))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Pattern> {
        self.patterns.iter()
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[allow(clippy::too_many_lines)]
fn builtin_patterns() -> Vec<Pattern> {
    use Severity::{Critical, High, Low, Medium, Unknown as Sev};

    vec![
        // ----- AWS -----
        Pattern::new(
            "aws_access_key",
            "AWS Access Key ID",
            High,
            r"\b((?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|APKA)[A-Z0-9]{16})\b",
        )
        .locked(),
        Pattern::new(
            "aws_secret_key",
            "AWS Secret Access Key",
            Critical,
            r#"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
        )
        .locked(),
        Pattern::new(
            "aws_session_token",
            "AWS Session Token",
            High,
            r#"(?i)aws[_-]?session[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?"#,
        ),
        // ----- Stripe -----
        Pattern::new(
            "stripe_secret",
            "Stripe Secret Key",
            Critical,
            r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b",
        )
        .locked(),
        Pattern::new(
            "stripe_publishable",
            "Stripe Publishable Key (low-sev — publishable by design)",
            Low,
            r"\b(pk_(?:live|test)_[0-9a-zA-Z]{24,})\b",
        ),
        // ----- GitHub -----
        Pattern::new(
            "github_token",
            "GitHub PAT / OAuth / App / Refresh / User Token",
            Critical,
            r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b",
        )
        .locked(),
        Pattern::new(
            "github_fine_grained",
            "GitHub Fine-Grained PAT",
            Critical,
            r"\b(github_pat_[A-Za-z0-9_]{82})\b",
        )
        .locked(),
        // ----- GitLab -----
        Pattern::new(
            "gitlab_pat",
            "GitLab Personal Access Token",
            Critical,
            r"\b(glpat-[A-Za-z0-9_-]{20})\b",
        )
        .locked(),
        // ----- LLM providers -----
        Pattern::new(
            "anthropic_key",
            "Anthropic API Key",
            Critical,
            r"\b(sk-ant-[A-Za-z0-9_-]{40,})\b",
        )
        .locked(),
        Pattern::new(
            "openai_key",
            "OpenAI API Key",
            Critical,
            r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,})\b",
        )
        .locked(),
        Pattern::new(
            "google_api_key",
            "Google / Firebase API Key",
            High,
            r"\b(AIza[0-9A-Za-z_-]{35})\b",
        ),
        // ----- Communications / SaaS -----
        Pattern::new(
            "slack_token",
            "Slack Token",
            High,
            r"\b(xox[abprs]-(?:\d+-)*[A-Za-z0-9-]{10,48})\b",
        ),
        Pattern::new(
            "slack_webhook",
            "Slack Incoming Webhook URL",
            Medium,
            r"\b(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)\b",
        ),
        Pattern::new(
            "twilio_key",
            "Twilio API Key SID",
            High,
            r"\b(SK[a-f0-9]{32})\b",
        ),
        Pattern::new(
            "sendgrid_key",
            "SendGrid API Key",
            High,
            r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b",
        ),
        Pattern::new(
            "mailgun_key",
            "Mailgun API Key",
            Medium,
            r"\b(key-[a-f0-9]{32})\b",
        ),
        Pattern::new(
            "datadog_api_key",
            "Datadog API Key (proximity-anchored)",
            High,
            // Bare 32-hex would collide with every md5; require a
            // datadog / dd_api_key style label nearby.
            r#"(?i)(?:dd|datadog)[_-]?api[_-]?key\s*[:=]\s*['"]?([a-f0-9]{32})['"]?"#,
        ),
        Pattern::new(
            "heroku_api_key",
            "Heroku API Key (HRKU-…)",
            High,
            r"\b(HRKU-[A-Za-z0-9_-]{36,})\b",
        ),
        Pattern::new(
            "npm_token",
            "npm registry token",
            High,
            r"\b(npm_[A-Za-z0-9]{36})\b",
        ),
        Pattern::new(
            "pypi_token",
            "PyPI upload token",
            High,
            r"\b(pypi-[A-Za-z0-9_-]{20,})\b",
        ),
        Pattern::new(
            "digitalocean_pat",
            "DigitalOcean Personal Access Token",
            High,
            r"\b(dop_v1_[a-f0-9]{64})\b",
        ),
        // ----- Cloud platforms -----
        Pattern::new(
            "gcp_service_account",
            "GCP Service Account JSON (private_key_id)",
            Critical,
            r#""type"\s*:\s*"service_account"[^}]*"private_key_id"\s*:\s*"([a-f0-9]{40})""#,
        )
        .locked(),
        Pattern::new(
            "azure_storage",
            "Azure Storage Account Connection String",
            Critical,
            r"DefaultEndpointsProtocol=https;AccountName=([A-Za-z0-9]+);AccountKey=([A-Za-z0-9+/=]{88});",
        )
        .locked(),
        // ----- Crypto material -----
        Pattern::new(
            "pem_private_key",
            "PEM-encoded Private Key",
            Critical,
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)",
        )
        .with_capture(1)
        .locked(),
        Pattern::new(
            "jwt",
            "JWT (header.payload.signature)",
            Medium,
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
        ),
        // ----- Database URLs -----
        Pattern::new(
            "postgres_url",
            "PostgreSQL URL with credentials",
            High,
            r#"\b(postgres(?:ql)?://[^:\s'"]+:[^@\s'"]+@[^\s'"]+)\b"#,
        ),
        Pattern::new(
            "mysql_url",
            "MySQL URL with credentials",
            High,
            r#"\b(mysql://[^:\s'"]+:[^@\s'"]+@[^\s'"]+)\b"#,
        ),
        Pattern::new(
            "mongodb_url",
            "MongoDB URL with credentials",
            High,
            r#"\b(mongodb(?:\+srv)?://[^:\s'"]+:[^@\s'"]+@[^\s'"]+)\b"#,
        ),
        Pattern::new(
            "redis_url_auth",
            "Redis URL with credentials",
            High,
            r#"\b(rediss?://[^:\s'"]*:[^@\s'"]+@[^\s'"]+)\b"#,
        ),
        // ----- Generic (the noisy one) -----
        Pattern::new(
            "secret_assignment",
            "Generic secret-shaped assignment",
            Sev,
            // Secret-ish variable names only — deliberately NOT bare `_key`
            // (floods on cache_key / sort_key / partition_key). The
            // classifier triages the residue.
            r#"(?i)(?:password|passwd|pwd|passphrase|secret|credential|token|bearer|api[_-]?key|apikey|access[_-]?key|private[_-]?key|signing[_-]?key|encryption[_-]?key|auth[_-]?token)\s*[:=]\s*['"]([^'"\s]{12,})['"]"#,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_compiles() {
        let r = PatternRegistry::builtin();
        assert!(r.len() > 20, "expected >20 patterns, got {}", r.len());
    }

    #[test]
    fn detects_aws_access_key() {
        let r = PatternRegistry::builtin();
        let hits = r.matches("AKIAIOSFODNN7EXAMPLE");
        assert!(!hits.is_empty());
        let (pattern, regex) = r.get(hits[0]).unwrap();
        assert_eq!(pattern.id, "aws_access_key");
        let caps = regex.captures("AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(&caps[1], "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn detects_stripe_test_key() {
        let r = PatternRegistry::builtin();
        let hits = r.matches("STRIPE = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc'");
        assert!(hits
            .iter()
            .any(|&i| r.get(i).unwrap().0.id == "stripe_secret"));
    }

    #[test]
    fn detects_github_pat() {
        let r = PatternRegistry::builtin();
        let line = "GH = 'ghp_1234567890abcdefghij1234567890abcdef1234'";
        assert!(!r.matches(line).is_empty());
    }

    #[test]
    fn secret_assignment_covers_widened_keywords() {
        let r = PatternRegistry::builtin();
        let is_secret_assign = |line: &str| {
            r.matches(line)
                .iter()
                .any(|&i| r.get(i).unwrap().0.id == "secret_assignment")
        };
        // Newly covered secret-ish names.
        assert!(is_secret_assign("AWS_ACCESS_KEY = 'wJalrXUtnFEMIK7MDENG'"));
        assert!(is_secret_assign("private_key = 'abcdef0123456789abcd'"));
        assert!(is_secret_assign(
            "CLIENT_CREDENTIAL = 'abcdef0123456789abcd'"
        ));
        assert!(is_secret_assign("passphrase = 'correcthorsebattery12'"));
        // Must NOT flood: a plain cache key is not a secret.
        assert!(!is_secret_assign("cache_key = 'user_12345_profile_v2'"));
    }
}
