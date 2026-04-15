use serde::{Deserialize, Serialize};

/// Classifier verdict per finding. `Unknown` is the default before
/// any classifier runs and the safe fallback when heuristics are
/// inconclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Looks like a live secret that shipped in production source.
    Real,
    /// Looks like a test fixture, mock, stub, example, doc, or dummy.
    Fixture,
    /// Cannot tell from context alone.
    #[default]
    Unknown,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::Fixture => "fixture",
            Self::Unknown => "unknown",
        }
    }

    /// Parse the case-insensitive form emitted by host LLMs ("REAL",
    /// "Fixture", etc).
    pub fn parse_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "real" => Self::Real,
            "fixture" => Self::Fixture,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
