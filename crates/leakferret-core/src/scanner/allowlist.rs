//! Inline allowlist pragmas.
//!
//! Operators can suppress individual findings by dropping a comment
//! pragma into the source file itself. This keeps the policy next to
//! the value it concerns and survives baseline-rotation churn.
//!
//! Recognised forms (case-insensitive on the literal `leakferret:allow`):
//!
//! ```text
//! # leakferret:allow
//! # leakferret:allow aws_access_key
//! # leakferret:allow aws_access_key reason="tutorial"
//! // leakferret:allow stripe_secret reason="known test key"
//! /* leakferret:allow */
//! ```
//!
//! Placement rules:
//!
//! * A pragma on the **same line** as a finding suppresses that line.
//! * A pragma on the **line immediately before** a finding suppresses
//!   the next non-blank line.
//! * If the optional `pattern_id` is present the pragma only suppresses
//!   findings with that `pattern_id`; otherwise it suppresses **all**
//!   patterns on the line.
//! * A line may carry multiple pragmas (e.g. one per `pattern_id`) — each
//!   is OR'd together when deciding whether to suppress.
//!
//! Suppressed findings are **dropped** by the scanner, not reclassified
//! as Fixture: they were operator-acknowledged false positives that
//! don't even need to show up in the report.

use std::collections::HashMap;

use regex::Regex;
use std::sync::LazyLock;

/// One parsed pragma. `pattern_id == None` means "suppress all
/// patterns on this line".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowPragma {
    pub pattern_id: Option<String>,
    pub reason: Option<String>,
}

/// Map from 1-indexed line number to the pragmas that apply to that
/// line. A finding on line `N` is suppressed iff `map.get(&N)` contains
/// either a generic pragma (no `pattern_id`) or a pragma whose
/// `pattern_id` matches the finding's pattern.
#[derive(Debug, Default, Clone)]
pub struct AllowlistMap {
    by_line: HashMap<usize, Vec<AllowPragma>>,
}

impl AllowlistMap {
    /// True if a finding at `line` with `pattern_id` should be
    /// suppressed.
    pub fn suppresses(&self, line: usize, pattern_id: &str) -> bool {
        let Some(pragmas) = self.by_line.get(&line) else {
            return false;
        };
        pragmas
            .iter()
            .any(|p| p.pattern_id.as_deref().is_none_or(|id| id == pattern_id))
    }

    /// Total number of pragmas parsed across all lines (counts
    /// duplicated entries on the propagated next-line slot too). Used
    /// by tests.
    pub fn len(&self) -> usize {
        self.by_line.values().map(Vec::len).sum()
    }

    /// True when no pragmas were parsed.
    pub fn is_empty(&self) -> bool {
        self.by_line.values().all(Vec::is_empty)
    }
}

/// Matches `leakferret:allow` optionally followed by a pattern id and
/// an optional `reason="..."` clause. The leading comment marker is
/// not needed — `#`, `//`, and `/*` all work because we match the
/// literal anywhere in the line.
static PRAGMA_RE: LazyLock<Regex> = LazyLock::new(|| {
    // pattern_id is a lowercase identifier with underscores; reason is
    // a double-quoted free-form string.
    Regex::new(
        r#"(?i)leakferret:allow(?:\s+(?P<id>[a-z][a-z0-9_]*))?(?:\s+reason\s*=\s*"(?P<reason>[^"]*)")?"#,
    )
    .expect("static allowlist regex must compile")
});

/// Scan a slice of source lines (newline-terminator stripped or kept,
/// both work) for allowlist pragmas. Returns a map from finding-line
/// numbers (1-indexed) to the pragmas that suppress them.
pub fn scan_for_pragmas(lines: &[&str]) -> AllowlistMap {
    let mut map: HashMap<usize, Vec<AllowPragma>> = HashMap::new();

    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1; // 1-indexed
        let stripped = raw.trim_end_matches('\n').trim_end_matches('\r');
        // Multiple pragmas may appear on the same line (rare but
        // possible if you stack different pattern ids).
        for caps in PRAGMA_RE.captures_iter(stripped) {
            let pragma = AllowPragma {
                pattern_id: caps.name("id").map(|m| m.as_str().to_ascii_lowercase()),
                reason: caps.name("reason").map(|m| m.as_str().to_string()),
            };
            // Apply to the line carrying the pragma…
            map.entry(line_no).or_default().push(pragma.clone());
            // …and to the next line, so `# leakferret:allow` ABOVE a
            // finding also works.
            map.entry(line_no + 1).or_default().push(pragma);
        }
    }

    AllowlistMap { by_line: map }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_of(src: &str) -> AllowlistMap {
        let lines: Vec<&str> = src.split_inclusive('\n').collect();
        scan_for_pragmas(&lines)
    }

    #[test]
    fn same_line_pragma_suppresses_finding() {
        let src = "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE' # leakferret:allow\n";
        let m = map_of(src);
        assert!(m.suppresses(1, "aws_access_key"));
        assert!(m.suppresses(1, "any_other_pattern"));
    }

    #[test]
    fn preceding_line_pragma_suppresses_next_line() {
        let src = "# leakferret:allow\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n";
        let m = map_of(src);
        assert!(m.suppresses(2, "aws_access_key"));
    }

    #[test]
    fn pattern_specific_pragma_only_suppresses_that_pattern() {
        let src = "AWS_KEY = 'X' # leakferret:allow aws_access_key\n";
        let m = map_of(src);
        assert!(m.suppresses(1, "aws_access_key"));
        assert!(!m.suppresses(1, "stripe_secret"));
    }

    #[test]
    fn generic_pragma_suppresses_all_patterns() {
        let src = "AWS_KEY = 'X' # leakferret:allow\n";
        let m = map_of(src);
        assert!(m.suppresses(1, "aws_access_key"));
        assert!(m.suppresses(1, "stripe_secret"));
    }

    #[test]
    fn pragma_with_reason_parses() {
        let src = r#"# leakferret:allow aws_access_key reason="tutorial fixture"
AWS_KEY = 'X'
"#;
        let m = map_of(src);
        assert!(m.suppresses(2, "aws_access_key"));
        // Reason is captured on the pragma carrier line.
        let p = m
            .by_line
            .get(&1)
            .expect("pragma present")
            .first()
            .expect("first");
        assert_eq!(p.reason.as_deref(), Some("tutorial fixture"));
    }

    #[test]
    fn slash_slash_and_block_comment_pragmas_work() {
        let src = "FOO = 'x' // leakferret:allow stripe_secret\nBAR = 'y' /* leakferret:allow */\n";
        let m = map_of(src);
        assert!(m.suppresses(1, "stripe_secret"));
        assert!(m.suppresses(2, "anything"));
    }

    #[test]
    fn multiple_pragmas_on_same_line_or_in_a_row() {
        let src =
            "# leakferret:allow aws_access_key\n# leakferret:allow stripe_secret\nFOO = 'x'\n";
        let m = map_of(src);
        // The pragma on line 2 suppresses line 3 for stripe_secret;
        // the pragma on line 1 suppresses line 2.
        assert!(m.suppresses(3, "stripe_secret"));
        assert!(m.suppresses(2, "aws_access_key"));
    }

    #[test]
    fn no_pragma_means_no_suppression() {
        let src = "AWS_KEY = 'AKIA...'\n";
        let m = map_of(src);
        assert!(!m.suppresses(1, "aws_access_key"));
        assert!(m.is_empty());
    }
}
