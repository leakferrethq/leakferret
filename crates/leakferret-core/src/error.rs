//! Crate-wide error type. Library-level errors use [`Error`] +
//! [`thiserror`] so callers can match on variants. The CLI wraps in
//! `anyhow::Error` for application-level reporting.

use std::path::PathBuf;

/// Crate `Result` alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors produced by the engine. Categorised so a caller can decide
/// whether to retry, surface, or swallow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O failed (file read, baseline write, etc).
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// I/O failed with no specific path context.
    #[error("I/O error: {0}")]
    BareIo(#[from] std::io::Error),

    /// Configuration is invalid (bad TOML, contradictory flags, etc).
    #[error("configuration error: {0}")]
    Config(String),

    /// Pattern compilation failed.
    #[error("invalid regex for pattern {name:?}: {source}")]
    Pattern {
        name: String,
        #[source]
        source: regex::Error,
    },

    /// JSON serialisation / deserialisation failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Catalog signature is missing or did not verify against the
    /// expected key. Treated as fatal — better to refuse a tampered
    /// fixture catalog than to false-negative a live secret.
    #[error("catalog signature verification failed: {0}")]
    CatalogSignature(String),

    /// Catalog payload is malformed.
    #[error("catalog parse error: {0}")]
    CatalogParse(String),

    /// HTTP transport error from a verifier.
    #[error("HTTP error contacting {provider}: {source}")]
    Http {
        provider: &'static str,
        #[source]
        source: reqwest::Error,
    },

    /// Verifier required additional context (e.g. AWS secret key
    /// paired with access key) and could not run.
    #[error("verifier {provider} needs additional context: {reason}")]
    VerifierContext {
        provider: &'static str,
        reason: String,
    },

    /// Baseline file is corrupt.
    #[error("baseline file corrupt: {0}")]
    Baseline(String),

    /// A file could not be classified by language.
    #[error("unsupported language for path: {0}")]
    UnsupportedLanguage(PathBuf),

    /// Generic catch-all. Use sparingly; prefer a specific variant.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Convenience builder for `Error::Io` so callers can `.map_err(|e| Error::io(path, e))`.
    pub fn io<P: Into<PathBuf>>(path: P, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
