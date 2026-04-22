//! Versioned fixture catalog. Lets the engine emit deterministic
//! `Verdict::Fixture` for known-public test credentials (Stripe test
//! keys, AWS canary patterns, JWT.io examples, …) without spending an
//! LLM call or a verifier round-trip on them.
//!
//! Catalog files are JSON. They MAY carry an Ed25519 signature in
//! `catalog.signature` over the canonical payload; if a public key is
//! configured, the signature must verify or the catalog is refused.

mod load;
mod lookup;
mod signature;

pub use load::{load_from_path, load_from_str};
pub use lookup::CatalogIndex;
pub use signature::{
    embedded_verifying_key, sign_catalog, verify_signature, SigningKey, VerifyingKey,
    EMBEDDED_PUBLIC_KEY,
};

use std::path::Path;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Verdict the catalog applies when it matches a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CatalogVerdict {
    /// Always a fixture. Stripe test key, AWS canary, JWT example.
    #[default]
    Fixture,
    /// A known-leaked secret rotated long ago — still a finding for
    /// audit purposes but ranked low.
    KnownLeaked,
    /// A honeytoken planted by a defender; matches should alert and
    /// raise to Critical regardless of pattern severity.
    Honeytoken,
}

/// How an entry matches a candidate value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum MatchStrategy {
    /// Cleartext exact match.
    Exact { value: String },
    /// SHA-256 hex hash exact match. Used for entries where shipping
    /// the cleartext would be undesirable.
    ExactHash { sha256: String },
    /// Regex match.
    Regex { pattern: String },
}

/// Trust level — community contribs default to off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Highest — published by the vendor itself.
    #[default]
    VendorPublished,
    /// Published in an RFC / IETF document.
    RfcPublished,
    /// Community contribution with two reviewer sign-offs.
    CommunityVerified,
    /// Community contribution without sign-off. Off by default.
    CommunityUnverified,
}

/// One catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub id: String,
    pub kind: String,
    #[serde(rename = "match")]
    pub matcher: MatchStrategy,
    pub source: String,
    #[serde(default)]
    pub source_checked_at: Option<String>,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub trust: TrustLevel,
    #[serde(default)]
    pub verdict: CatalogVerdict,
}

/// The full catalog file as it lives on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogFile {
    pub schema_version: u32,
    pub catalog_version: String,
    pub license: String,
    /// Ed25519 signature over the canonical payload (see
    /// `signature.rs`). Optional during local development; required
    /// when fetched from the catalog CDN.
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signing_key_id: Option<String>,
    pub entries: Vec<CatalogEntry>,
}

/// Loaded, indexed catalog ready to answer lookups.
#[derive(Debug)]
pub struct Catalog {
    pub file: CatalogFile,
    pub index: CatalogIndex,
}

impl Catalog {
    /// Load from a path. If `expected_key` is `Some`, the signature
    /// must verify against that public key.
    pub fn load(path: &Path, expected_key: Option<&VerifyingKey>) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| crate::Error::io(path, e))?;
        Self::parse(&raw, expected_key)
    }

    /// Parse from a JSON string. Same signature rules as [`Self::load`].
    pub fn parse(raw: &str, expected_key: Option<&VerifyingKey>) -> Result<Self> {
        let file: CatalogFile = serde_json::from_str(raw)?;
        if let Some(key) = expected_key {
            let sig = file
                .signature
                .as_deref()
                .ok_or_else(|| crate::Error::CatalogSignature("missing signature".into()))?;
            verify_signature(&file, sig, key)?;
        }
        let index = CatalogIndex::from_entries(&file.entries)?;
        Ok(Self { file, index })
    }

    /// Empty catalog. Useful in tests and as a fallback when no
    /// catalog file is configured.
    pub fn empty() -> Self {
        Self {
            file: CatalogFile {
                schema_version: 1,
                catalog_version: "empty".into(),
                license: "CC0-1.0".into(),
                signature: None,
                signing_key_id: None,
                entries: vec![],
            },
            index: CatalogIndex::default(),
        }
    }

    /// Look up a candidate value. Returns the verdict + matching entry
    /// id if any entry matched.
    pub fn lookup(&self, value: &str) -> Option<(CatalogVerdict, &str)> {
        self.index
            .lookup(value)
            .and_then(|i| self.file.entries.get(i).map(|e| (e.verdict, e.id.as_str())))
    }
}

/// Lookup-only view over a single catalog entry. Mostly used by the
/// reporter to show *why* a finding was downgraded.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogHit<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub source: &'a str,
    pub verdict: CatalogVerdict,
}

/// Re-export the indexable map for downstream consumers.
pub type EntriesById = IndexMap<String, CatalogEntry>;
