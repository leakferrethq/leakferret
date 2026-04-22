//! In-memory index over catalog entries for O(1) exact lookup and
//! linear-scan regex matching. Built once from the loaded JSON.

use std::collections::HashMap;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::Result;

use super::{CatalogEntry, MatchStrategy};

#[derive(Debug, Default)]
pub struct CatalogIndex {
    by_exact: HashMap<String, usize>,
    by_hash: HashMap<String, usize>,
    by_regex: Vec<(Regex, usize)>,
}

impl CatalogIndex {
    pub fn from_entries(entries: &[CatalogEntry]) -> Result<Self> {
        let mut by_exact = HashMap::new();
        let mut by_hash = HashMap::new();
        let mut by_regex = Vec::new();

        for (idx, e) in entries.iter().enumerate() {
            match &e.matcher {
                MatchStrategy::Exact { value } => {
                    by_exact.insert(value.clone(), idx);
                }
                MatchStrategy::ExactHash { sha256 } => {
                    by_hash.insert(sha256.to_ascii_lowercase(), idx);
                }
                MatchStrategy::Regex { pattern } => {
                    let regex = Regex::new(pattern).map_err(|e| crate::Error::Pattern {
                        name: format!("catalog:{}", entries[idx].id),
                        source: e,
                    })?;
                    by_regex.push((regex, idx));
                }
            }
        }

        Ok(Self {
            by_exact,
            by_hash,
            by_regex,
        })
    }

    /// Look up a candidate value. Returns the entry index of the
    /// first matching strategy, or `None`.
    pub fn lookup(&self, value: &str) -> Option<usize> {
        if let Some(&idx) = self.by_exact.get(value) {
            return Some(idx);
        }
        let hash = hex::encode(Sha256::digest(value.as_bytes()));
        if let Some(&idx) = self.by_hash.get(&hash) {
            return Some(idx);
        }
        for (re, idx) in &self.by_regex {
            if re.is_match(value) {
                return Some(*idx);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CatalogVerdict;

    fn entry(id: &str, m: MatchStrategy) -> CatalogEntry {
        CatalogEntry {
            id: id.into(),
            kind: "test".into(),
            matcher: m,
            source: "test".into(),
            source_checked_at: None,
            rationale: None,
            trust: crate::catalog::TrustLevel::default(),
            verdict: CatalogVerdict::Fixture,
        }
    }

    #[test]
    fn exact_match() {
        let entries = vec![entry(
            "a",
            MatchStrategy::Exact {
                value: "hello".into(),
            },
        )];
        let idx = CatalogIndex::from_entries(&entries).unwrap();
        assert_eq!(idx.lookup("hello"), Some(0));
        assert_eq!(idx.lookup("world"), None);
    }

    #[test]
    fn hash_match() {
        let value = "world";
        let hash = hex::encode(Sha256::digest(value.as_bytes()));
        let entries = vec![entry("h", MatchStrategy::ExactHash { sha256: hash })];
        let idx = CatalogIndex::from_entries(&entries).unwrap();
        assert_eq!(idx.lookup(value), Some(0));
    }

    #[test]
    fn regex_match() {
        let entries = vec![entry(
            "r",
            MatchStrategy::Regex {
                pattern: r"^AKIAIOSFODNN[0-9A-Z]EXAMPLE$".into(),
            },
        )];
        let idx = CatalogIndex::from_entries(&entries).unwrap();
        assert_eq!(idx.lookup("AKIAIOSFODNN7EXAMPLE"), Some(0));
        assert_eq!(idx.lookup("AKIAIOSFODNN_REAL_KEY"), None);
    }
}
