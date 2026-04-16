//! Regex pattern registry — the cheap pre-filter pass that turns
//! candidate lines into `Finding`s before the classifier and verifier
//! get involved.
//!
//! Design rules every pattern follows:
//!   1. The capture group 1 is the secret value (or the whole match
//!      if the surrounding chrome is the whole pattern).
//!   2. The description is short enough to fit in a status-bar tooltip.
//!   3. Provider-specific patterns are tight enough that they're
//!      useful even without the classifier; the generic
//!      `secret_assignment` pattern is the noisy catch-all.

mod registry;

pub use registry::PatternRegistry;

use serde::{Deserialize, Serialize};

use crate::finding::Severity;

/// Stable identifier for a pattern (e.g. `"aws_access_key"`).
pub type PatternId = String;

/// One regex-based pattern. Compiled once at startup into
/// [`PatternRegistry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub id: PatternId,
    pub description: String,
    pub severity: Severity,
    /// Raw regex source. The compiled form lives in [`PatternRegistry`].
    pub regex: String,
    /// Which capture group holds the secret value. Usually 1; 0 means
    /// "whole match is the secret".
    #[serde(default = "default_capture")]
    pub capture_group: usize,
    /// True if this pattern is allowed to be disabled by the user via
    /// config. Set to false for the most dangerous patterns
    /// (private keys, AWS access keys) so they can't be silenced.
    #[serde(default = "default_true")]
    pub user_toggleable: bool,
}

fn default_capture() -> usize {
    1
}

fn default_true() -> bool {
    true
}

impl Pattern {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        regex: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            severity,
            regex: regex.into(),
            capture_group: 1,
            user_toggleable: true,
        }
    }

    pub fn with_capture(mut self, n: usize) -> Self {
        self.capture_group = n;
        self
    }

    pub fn locked(mut self) -> Self {
        self.user_toggleable = false;
        self
    }
}

/// Path-based fixture hints. Used by the offline classifier and by
/// SARIF level downgrades.
pub const FIXTURE_PATH_HINTS: &[&str] = &[
    "spec/",
    "test/",
    "tests/",
    "__tests__/",
    "fixtures/",
    "examples/",
    "docs/",
    "doc/",
    "example/",
    "sample/",
    "samples/",
    "demo/",
    "tutorial/",
    ".env.example",
    ".env.sample",
    ".env.template",
    "mock/",
    "mocks/",
    "stub/",
    "stubs/",
    "dummy/",
];

/// App-path prefixes that raise the prior toward `Real` for the
/// offline classifier.
pub const APP_PATH_PREFIXES: &[&str] = &[
    "app/",
    "lib/",
    "src/",
    "config/",
    "cmd/",
    "services/",
    "pkg/",
    "internal/",
];

pub fn looks_like_fixture_path(path: &str) -> bool {
    let lower = path.replace('\\', "/");
    FIXTURE_PATH_HINTS.iter().any(|hint| lower.contains(hint))
}

pub fn looks_like_app_path(path: &str) -> bool {
    let lower = path.replace('\\', "/");
    APP_PATH_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_path_hints_hit_spec_and_examples() {
        assert!(looks_like_fixture_path("spec/models/user_spec.rb"));
        assert!(looks_like_fixture_path("docs/setup.md"));
        assert!(looks_like_fixture_path(".env.example"));
        assert!(!looks_like_fixture_path("app/services/billing.rb"));
    }

    #[test]
    fn app_path_prefixes_hit_lib_and_app() {
        assert!(looks_like_app_path("app/controllers/api.rb"));
        assert!(looks_like_app_path("internal/auth/token.go"));
        assert!(!looks_like_app_path("spec/test.rb"));
    }

    #[test]
    fn normalises_windows_backslashes() {
        assert!(looks_like_fixture_path("spec\\models\\user_spec.rb"));
        assert!(looks_like_app_path("app\\controllers\\api.rb"));
    }
}
