//! Pure-heuristic classifier. Decides REAL / FIXTURE / UNKNOWN based
//! on:
//!
//!   1. Catalog hit. Three sub-cases driven by [`CatalogVerdict`]:
//!      * Fixture        → `Verdict::Fixture`, confidence 1.0.
//!      * `KnownLeaked`    → `Verdict::Real`, severity High, confidence 1.0.
//!      * Honeytoken     → `Verdict::Real`, severity **Critical** (mutated
//!        even if the pattern said something lower), confidence 1.0,
//!        alert-grade reason string.
//!   2. Verifier outcome (deterministic REAL when verified).
//!   3. Path hints (`spec/`, `fixtures/`, `.env.example`).
//!   4. Obvious dummy markers in the secret value (`example`, `xxxx`).
//!   5. Env-var references (`$VAR`, `ENV[...]`, `process.env.X`) — never a leak.
//!   6. Template placeholders, interpolation, and low-entropy fillers
//!      (`{password}`, `#{secret}`, `0{32}`).
//!   7. Secret-store references (`from_secret`, `ExternalSecrets` paths).
//!   8. Pattern severity in an app path (`app/`, `lib/`, `src/`).

use crate::catalog::{Catalog, CatalogVerdict};
use crate::finding::{Finding, Severity, Verdict};
use crate::patterns::{looks_like_app_path, looks_like_fixture_path};
use crate::verifier::VerificationOutcome;

use super::Classifier;

/// Offline classifier. Holds a reference to a catalog so it can
/// resolve fixture hits without re-reading the file.
#[derive(Debug)]
pub struct OfflineClassifier<'a> {
    catalog: &'a Catalog,
    /// Whether provider verification was attempted this run. Drives the
    /// wording of the inconclusive reason so it never tells the user to
    /// "run a verifier" that already ran.
    verify_attempted: bool,
}

impl<'a> OfflineClassifier<'a> {
    pub fn new(catalog: &'a Catalog) -> Self {
        Self {
            catalog,
            verify_attempted: false,
        }
    }

    /// Record that provider verification ran before this classification.
    #[must_use]
    pub fn verification_attempted(mut self, attempted: bool) -> Self {
        self.verify_attempted = attempted;
        self
    }
}

/// Case-insensitive substring markers that betray a placeholder value.
/// Deliberately conservative — only tokens vanishingly unlikely to appear
/// inside a real, high-entropy credential, so a genuine leak is never
/// suppressed. (Compared case-insensitively against the lowercased value.)
const DUMMY_MARKERS: &[&str] = &[
    "example",
    "xxxx",
    "test_xxx",
    "placeholder",
    "redacted",
    "changeme",
    "change_me",
    "change-me",
    "your_",
    "your-",
    "<your",
    "todo",
    "sample",
    "dummy",
    "fakekey",
    "fake_key",
    "notreal",
    "not_real",
    "donotuse",
    "do_not_use",
    "replaceme",
    "replace_me",
    "insert_your",
    "lorem",
];

fn obvious_dummy(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    DUMMY_MARKERS.iter().any(|m| lower.contains(m))
}

/// Runtime env-var accessors that mark a value as a reference, not a literal.
const ENV_REF_TOKENS: &[&str] = &[
    "env[",
    "env.fetch",
    "process.env",
    "os.environ",
    "os.getenv",
    "system.getenv",
    "getenv(",
    "viper.get",
    "rails.application.credentials",
    "credentials.dig",
    "#{env",
    "<%= env",
];

/// Interpolation / format tokens that mark a value as a placeholder.
const PLACEHOLDER_TOKENS: &[&str] = &["{{", "}}", "#{", "${", "%{", "<%=", "%s", "%d"];

/// True when the captured value is an environment-variable reference
/// rather than a hardcoded literal — the code is *already* reading the
/// secret from the environment. Flagging these is a false positive for a
/// tool whose whole thesis is "move secrets into env vars."
fn looks_like_var_reference(value: &str) -> bool {
    let t = value
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');
    if t.starts_with("${") && t.ends_with('}') {
        return true; // ${VAR} — braced, unambiguous
    }
    // $VAR — a shell identifier only. Excludes bcrypt hashes (`$2a$…`, a
    // digit right after `$`) and `$`-prefixed literal passwords with any
    // non-identifier character, so a real secret is never suppressed.
    if let Some(rest) = t.strip_prefix('$') {
        if rest
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return true;
        }
    }
    if t.len() > 2 && t.starts_with('%') && t.ends_with('%') {
        return true; // %VAR% (Windows)
    }
    let lower = t.to_ascii_lowercase();
    ENV_REF_TOKENS.iter().any(|r| lower.contains(r))
}

/// True when the captured value is a template placeholder or format
/// token — `{password}`, `#{secret}`, `${TOKEN}`, `<api-key>`, `****` —
/// rather than a literal secret.
fn looks_like_placeholder(value: &str) -> bool {
    let t = value
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');
    if t.is_empty() {
        return true;
    }
    let wrapped = (t.starts_with('{') && t.ends_with('}'))
        || (t.starts_with('<') && t.ends_with('>'))
        || (t.starts_with("#{") && t.ends_with('}'))
        || (t.starts_with("${") && t.ends_with('}'))
        || (t.starts_with("%{") && t.ends_with('}'));
    if wrapped {
        return true;
    }
    if PLACEHOLDER_TOKENS.iter().any(|tok| t.contains(tok)) {
        return true;
    }
    // All-mask values: ****, xxxx, ...., ____, ----.
    let mask = t.trim_matches(|c| matches!(c, '*' | 'x' | 'X' | '.' | '_' | '-'));
    if mask.is_empty() && t.len() >= 3 {
        return true;
    }
    // Very low character diversity (0{32}, aaaa…, repeated single char) —
    // a placeholder, never a real high-entropy secret.
    if t.len() >= 8 {
        let distinct: std::collections::HashSet<char> = t.chars().collect();
        if distinct.len() <= 2 {
            return true;
        }
    }
    false
}

/// True when the finding is a declarative reference to a secret store
/// (Kubernetes `ExternalSecrets`, `from_secret:`, `secretKeyRef`, …) — the
/// captured value is a reference name or path, not a literal secret.
fn is_secret_reference(value: &str, context: &[String]) -> bool {
    const REF_KEYS: &[&str] = &[
        "from_secret",
        "externalsecret",
        "external-secret",
        "secretkeyref",
        "valuefrom",
        "secretname",
        "secretref",
        "secret_ref",
    ];
    let v = value
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');
    // The reference keyword must be on the *same* line as the captured value
    // (a declaration like `from_secret: "name"`), not merely nearby — so a
    // real secret a few lines from a `secretKeyRef` is never suppressed.
    if context.iter().any(|line| {
        line.contains(v) && {
            let low = line.to_ascii_lowercase();
            REF_KEYS.iter().any(|k| low.contains(k))
        }
    }) {
        return true;
    }
    // ExternalSecrets-style path: lowercase words/digits split by '/', two
    // or more segments. Real secrets are high-entropy (mixed case), so this
    // won't swallow a base64 key that merely contains '/'.
    v.contains('/')
        && v.split('/').filter(|s| !s.is_empty()).count() >= 2
        && v.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '/' | '-' | '_' | '.')
        })
}

impl Classifier for OfflineClassifier<'_> {
    fn classify(&self, findings: &mut [Finding]) {
        for f in findings {
            // 1) Catalog wins. Three deterministic sub-verdicts.
            if let Some((catalog_verdict, id)) = self.catalog.lookup(&f.r#match) {
                match catalog_verdict {
                    CatalogVerdict::Fixture => {
                        f.verdict = Verdict::Fixture;
                        f.reason = Some(format!("Catalog hit: {id}"));
                        f.confidence = Some(1.0);
                    }
                    CatalogVerdict::KnownLeaked => {
                        f.verdict = Verdict::Real;
                        f.severity = Severity::High;
                        f.reason = Some(format!("Catalog hit: known historical leak ({id})"));
                        f.confidence = Some(1.0);
                    }
                    CatalogVerdict::Honeytoken => {
                        f.verdict = Verdict::Real;
                        // Mutate severity even if the pattern said lower —
                        // honeytoken trips are always alert-grade.
                        f.severity = Severity::Critical;
                        f.reason = Some(format!(
                            "HONEYTOKEN TRIPPED: {id}. This match indicates unauthorized access to source containing a planted canary."
                        ));
                        f.confidence = Some(1.0);
                    }
                }
                continue;
            }

            // 2) Verifier outcome trumps heuristic.
            match &f.verification {
                Some(VerificationOutcome::Verified { provider, .. }) => {
                    f.verdict = Verdict::Real;
                    f.reason = Some(format!("Verified live with {provider}"));
                    f.confidence = Some(1.0);
                    continue;
                }
                Some(VerificationOutcome::Invalid { provider, .. }) => {
                    f.verdict = Verdict::Fixture;
                    f.reason = Some(format!("{provider} rejected — key not currently active"));
                    f.confidence = Some(0.85);
                    continue;
                }
                _ => {}
            }

            let path_str = f.path.to_string_lossy();

            // 3) Path hints.
            if looks_like_fixture_path(&path_str) {
                f.verdict = Verdict::Fixture;
                f.reason = Some(format!(
                    "Path matches fixture/test/example heuristic ({path_str})"
                ));
                f.confidence = Some(0.7);
                continue;
            }

            // 4) Obvious dummies.
            if obvious_dummy(&f.r#match) {
                f.verdict = Verdict::Fixture;
                f.reason = Some(
                    "Matched value contains a documented dummy marker (example / xxxx / placeholder)"
                        .into(),
                );
                f.confidence = Some(0.9);
                continue;
            }

            // 4b) Env-var reference — the code already reads the secret from
            // the environment, so it is not a hardcoded literal at all. Must
            // beat the app-path → REAL rule below.
            if looks_like_var_reference(&f.r#match) {
                f.verdict = Verdict::Fixture;
                f.reason = Some(
                    "Value is an environment-variable reference, not a hardcoded secret".into(),
                );
                f.confidence = Some(0.95);
                continue;
            }

            // 4c) Template placeholder / interpolation token.
            if looks_like_placeholder(&f.r#match) {
                f.verdict = Verdict::Fixture;
                f.reason = Some("Value is a template placeholder, not a literal secret".into());
                f.confidence = Some(0.9);
                continue;
            }

            // 4d) Reference to a secret store (ExternalSecrets, from_secret,
            // secretKeyRef) — a reference name/path, not a literal secret.
            if is_secret_reference(&f.r#match, &f.context) {
                f.verdict = Verdict::Fixture;
                f.reason = Some("Value references a secret store, not a hardcoded secret".into());
                f.confidence = Some(0.9);
                continue;
            }

            // 5) High-severity in app path.
            if f.severity.is_high_or_above() && looks_like_app_path(&path_str) {
                f.verdict = Verdict::Real;
                f.reason = Some(format!(
                    "High-severity pattern in application path ({path_str})"
                ));
                f.confidence = Some(0.65);
                continue;
            }

            f.verdict = Verdict::Unknown;
            f.reason = Some(match (&f.verification, self.verify_attempted) {
                // A verifier ran but could not get a definitive answer
                // (network error, rate limit, missing paired secret).
                (Some(VerificationOutcome::Unverified { provider, reason }), _) => {
                    if provider == "trufflehog" && reason.contains("not installed") {
                        // The only verifier was the optional trufflehog fallback,
                        // which isn't installed — say that plainly rather than
                        // surfacing it as a failed check.
                        "Heuristics inconclusive and no native verifier covers this key type (install trufflehog for broader verification coverage)."
                            .into()
                    } else {
                        format!(
                            "Heuristics inconclusive; provider check with {provider} was inconclusive ({reason})"
                        )
                    }
                }
                // Verification ran this pass, but no verifier confirmed this
                // (often: no provider verifier exists for this key type).
                (_, true) => "Heuristics inconclusive and no provider confirmed it live; classify with an agent/LLM for higher precision."
                    .into(),
                // Verification was not attempted (offline `scan`).
                (_, false) => "Heuristics inconclusive; run `verify` or classify with an agent/LLM for higher precision."
                    .into(),
            });
            f.confidence = Some(0.3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{CatalogEntry, CatalogFile, CatalogIndex, CatalogVerdict, MatchStrategy};
    use crate::finding::Severity;
    use std::path::PathBuf;

    fn finding(path: &str, value: &str, sev: Severity) -> Finding {
        Finding {
            path: PathBuf::from(path),
            line: 1,
            column: 1,
            r#match: value.into(),
            pattern: "x".into(),
            severity: sev,
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

    /// Construct an in-memory catalog containing a single entry with
    /// the requested verdict. Used by the catalog-branch tests below.
    fn catalog_with(value: &str, verdict: CatalogVerdict, id: &str) -> Catalog {
        let entry = CatalogEntry {
            id: id.into(),
            kind: "test".into(),
            matcher: MatchStrategy::Exact {
                value: value.into(),
            },
            source: "test".into(),
            source_checked_at: None,
            rationale: None,
            trust: crate::catalog::TrustLevel::default(),
            verdict,
        };
        let entries = vec![entry];
        let index = CatalogIndex::from_entries(&entries).expect("index");
        let file = CatalogFile {
            schema_version: 1,
            catalog_version: "test".into(),
            license: "CC0-1.0".into(),
            signature: None,
            signing_key_id: None,
            entries,
        };
        Catalog { file, index }
    }

    #[test]
    fn marks_fixture_path_as_fixture() {
        let catalog = Catalog::empty();
        let mut fs = vec![finding(
            "spec/fixtures/keys.rb",
            "AKIAREAL12345BUTSPEC",
            Severity::High,
        )];
        OfflineClassifier::new(&catalog).classify(&mut fs);
        assert_eq!(fs[0].verdict, Verdict::Fixture);
    }

    #[test]
    fn unverified_outcome_reports_inconclusive_not_run_a_verifier() {
        // A verifier ran but couldn't get a definitive answer. The reason
        // must reflect that — never tell the user to "run with verifier".
        let catalog = Catalog::empty();
        let mut f = finding("notes.txt", "Zk9mQ2pR7vT4wL8bY6cF1dH5", Severity::Low);
        f.verification = Some(VerificationOutcome::Unverified {
            provider: "github".into(),
            reason: "unexpected HTTP 429".into(),
        });
        OfflineClassifier::new(&catalog)
            .verification_attempted(true)
            .classify(std::slice::from_mut(&mut f));
        assert_eq!(f.verdict, Verdict::Unknown);
        let reason = f.reason.unwrap();
        assert!(reason.contains("github"), "names the provider: {reason}");
        assert!(
            !reason.contains("run `verify`") && !reason.contains("run with"),
            "must not tell the user to run a verifier that already ran: {reason}"
        );
    }

    #[test]
    fn marks_high_sev_in_app_path_as_real() {
        let catalog = Catalog::empty();
        let mut fs = vec![finding(
            "app/config.rb",
            "AKIAREAL12345CONFIG",
            Severity::High,
        )];
        OfflineClassifier::new(&catalog).classify(&mut fs);
        assert_eq!(fs[0].verdict, Verdict::Real);
    }

    #[test]
    fn dummy_marker_overrides_to_fixture() {
        let catalog = Catalog::empty();
        let mut fs = vec![finding(
            "app/config.rb",
            "AKIAIOSFODNN7EXAMPLE",
            Severity::High,
        )];
        OfflineClassifier::new(&catalog).classify(&mut fs);
        assert_eq!(fs[0].verdict, Verdict::Fixture);
    }

    #[test]
    fn env_var_reference_is_not_a_secret() {
        let catalog = Catalog::empty();
        // All in an *app* path with High severity — must still be fixture,
        // because the value is an env-var reference, not a literal.
        let cases = [
            "$PG_PASSWORD",
            "${API_TOKEN}",
            "process.env.SECRET",
            "ENV['KEY']",
        ];
        for v in cases {
            let mut fs = vec![finding("app/config.rb", v, Severity::High)];
            OfflineClassifier::new(&catalog).classify(&mut fs);
            assert_eq!(fs[0].verdict, Verdict::Fixture, "{v} should be fixture");
        }
    }

    #[test]
    fn template_placeholder_is_not_a_secret() {
        let catalog = Catalog::empty();
        let cases = ["{password_value}", "#{secret}", "<api-key>", "****"];
        for v in cases {
            let mut fs = vec![finding("app/config.rb", v, Severity::High)];
            OfflineClassifier::new(&catalog).classify(&mut fs);
            assert_eq!(fs[0].verdict, Verdict::Fixture, "{v} should be fixture");
        }
    }

    #[test]
    fn dummy_name_markers_are_fixture() {
        let catalog = Catalog::empty();
        for v in [
            "sample_token",
            "your_api_key",
            "changeme123",
            "do_not_use_this",
        ] {
            let mut fs = vec![finding("app/config.rb", v, Severity::High)];
            OfflineClassifier::new(&catalog).classify(&mut fs);
            assert_eq!(fs[0].verdict, Verdict::Fixture, "{v} should be fixture");
        }
    }

    #[test]
    fn real_looking_key_in_app_path_is_still_real() {
        // Regression: the new heuristics must not swallow a genuine
        // high-entropy secret sitting in application code.
        let catalog = Catalog::empty();
        let mut fs = vec![finding(
            "app/config.rb",
            "AKIAZ8K2QWERTY12POIU",
            Severity::High,
        )];
        OfflineClassifier::new(&catalog).classify(&mut fs);
        assert_eq!(fs[0].verdict, Verdict::Real);
    }

    #[test]
    fn bcrypt_and_dollar_literals_are_not_suppressed() {
        // Recall guard: a $-prefixed value that is NOT a plain shell
        // identifier (bcrypt hash, special chars) must never be treated as
        // an env-var reference and suppressed.
        let catalog = Catalog::empty();
        for v in [
            "$2a$10$N9qo8uLOickgx2ZMRZoMye123456789012345678901234",
            "$ecret-P@ssw0rd-real-value-1234",
        ] {
            let mut fs = vec![finding("app/config.rb", v, Severity::High)];
            OfflineClassifier::new(&catalog).classify(&mut fs);
            assert_ne!(
                fs[0].verdict,
                Verdict::Fixture,
                "{v} must not be suppressed"
            );
        }
    }

    #[test]
    fn low_diversity_values_are_placeholders() {
        let catalog = Catalog::empty();
        for v in ["00000000000000000000000000000000", "aaaaaaaaaaaa"] {
            let mut fs = vec![finding("app/config.rb", v, Severity::High)];
            OfflineClassifier::new(&catalog).classify(&mut fs);
            assert_eq!(fs[0].verdict, Verdict::Fixture, "{v} should be fixture");
        }
    }

    #[test]
    fn secret_store_references_are_not_secrets() {
        let catalog = Catalog::empty();
        // By context keyword (from_secret).
        let mut f = finding(
            "infra/idp.yaml",
            "google_workspace_client_secret",
            Severity::High,
        );
        f.context =
            vec!["client_secret: { from_secret: \"google_workspace_client_secret\" }".into()];
        let mut fs = vec![f];
        OfflineClassifier::new(&catalog).classify(&mut fs);
        assert_eq!(
            fs[0].verdict,
            Verdict::Fixture,
            "from_secret ref should be fixture"
        );

        // By ExternalSecrets path shape.
        let mut fs2 = vec![finding(
            "app/values.yaml",
            "go-worker-hub/prod/deploy/credentials",
            Severity::High,
        )];
        OfflineClassifier::new(&catalog).classify(&mut fs2);
        assert_eq!(
            fs2[0].verdict,
            Verdict::Fixture,
            "external-secret path should be fixture"
        );
    }

    #[test]
    fn known_leaked_catalog_hit_is_real_high() {
        let value = "AKIAREALCANARY000001";
        let catalog = catalog_with(value, CatalogVerdict::KnownLeaked, "ht.aws.example-leak");
        let mut fs = vec![finding("app/config.rb", value, Severity::Low)];
        OfflineClassifier::new(&catalog).classify(&mut fs);
        assert_eq!(fs[0].verdict, Verdict::Real);
        assert_eq!(fs[0].severity, Severity::High);
        assert!(fs[0]
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("historical leak"));
    }

    #[test]
    fn honeytoken_catalog_hit_is_critical_even_when_pattern_was_low() {
        let value = "AKIAHONEYTOKEN0000001";
        let catalog = catalog_with(value, CatalogVerdict::Honeytoken, "ht.aws.acme.001");
        // Pattern's natural severity is Low — the classifier must raise it.
        let mut fs = vec![finding("app/config.rb", value, Severity::Low)];
        OfflineClassifier::new(&catalog).classify(&mut fs);
        assert_eq!(fs[0].verdict, Verdict::Real);
        assert_eq!(
            fs[0].severity,
            Severity::Critical,
            "honeytoken must mutate severity to Critical regardless of pattern"
        );
        let reason = fs[0].reason.as_deref().unwrap_or_default();
        assert!(
            reason.starts_with("HONEYTOKEN TRIPPED"),
            "reason was {reason}"
        );
        assert!(reason.contains("ht.aws.acme.001"));
    }

    #[test]
    fn honeytoken_critical_when_pattern_was_unknown() {
        let value = "AKIAHONEYTOKEN0000002";
        let catalog = catalog_with(value, CatalogVerdict::Honeytoken, "ht.aws.acme.002");
        let mut fs = vec![finding("app/config.rb", value, Severity::Unknown)];
        OfflineClassifier::new(&catalog).classify(&mut fs);
        assert_eq!(fs[0].severity, Severity::Critical);
    }
}
