use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::finding::Fingerprint;
use crate::Result;

/// Lifecycle status of a known secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    /// Last verifier run confirmed live. Block in CI.
    #[default]
    Active,
    /// Was verified live previously; latest verification failed.
    /// Treated as "ever-verified — still a historical leak."
    Rotated,
    /// Catalog hit — never block.
    Fixture,
    /// Operator-acknowledged false positive.
    Ignored,
}

/// Where this fingerprint has been seen.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineExposure {
    pub branches_seen: Vec<String>,
    pub tags_seen: Vec<String>,
    #[serde(default)]
    pub public_repo: bool,
    #[serde(default)]
    pub blast_radius: Option<String>,
}

/// One entry in the current-state baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: Fingerprint,
    pub kind: String,
    /// Redacted preview for human readability (`AKIA...MPLE`).
    pub key_preview: String,
    pub status: BaselineStatus,
    pub first_seen_at: DateTime<Utc>,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub verification_attempts: u32,
    pub ever_verified: bool,
    pub first_path: Option<PathBuf>,
    pub first_line: Option<usize>,
    #[serde(default)]
    pub exposure: BaselineExposure,
}

/// The full baseline file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: u32,
    pub repo_id: String,
    /// Map keyed by fingerprint for O(1) lookup.
    pub entries: BTreeMap<String, BaselineEntry>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            schema_version: 1,
            repo_id: uuid::Uuid::new_v4().to_string(),
            entries: BTreeMap::new(),
        }
    }
}

/// Load `.leakferret-baseline.json` at `path`. If missing, return a
/// fresh `Baseline` with a new `repo_id`. Corrupt JSON is an error.
pub fn load_or_init(path: &Path) -> Result<Baseline> {
    if !path.exists() {
        return Ok(Baseline::default());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| crate::Error::io(path, e))?;
    serde_json::from_str(&raw)
        .map_err(|e| crate::Error::Baseline(format!("{}: {e}", path.display())))
}

/// Persist `baseline` to `path` atomically (write-then-rename).
pub fn save(path: &Path, baseline: &Baseline) -> Result<()> {
    let raw = serde_json::to_string_pretty(baseline)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, raw).map_err(|e| crate::Error::io(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| crate::Error::io(path, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_returns_default_when_missing() {
        let tmp = TempDir::new().unwrap();
        let b = load_or_init(&tmp.path().join("baseline.json")).unwrap();
        assert_eq!(b.schema_version, 1);
        assert!(b.entries.is_empty());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("baseline.json");
        let mut b = Baseline::default();
        b.entries.insert(
            "fp1".into(),
            BaselineEntry {
                fingerprint: Fingerprint("fp1".into()),
                kind: "aws_access_key".into(),
                key_preview: "AKIA...XYZ".into(),
                status: BaselineStatus::Active,
                first_seen_at: Utc::now(),
                last_verified_at: None,
                verification_attempts: 1,
                ever_verified: true,
                first_path: Some(PathBuf::from("app/x.rb")),
                first_line: Some(12),
                exposure: BaselineExposure::default(),
            },
        );
        save(&path, &b).unwrap();
        let loaded = load_or_init(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
    }
}
