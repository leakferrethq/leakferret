//! Append-only history log (`.leakferret-history.jsonl`). One JSON
//! object per line, never edited in place.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::finding::Fingerprint;
use crate::Result;

/// What kind of event happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HistoryEventKind {
    Detected,
    VerifiedLive,
    VerifyFailed,
    StatusChange,
    Ignored,
    Acknowledged,
}

/// One audit-log event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEvent {
    pub ts: DateTime<Utc>,
    pub event: HistoryEventKind,
    pub fingerprint: Fingerprint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub extra: Value,
}

impl HistoryEvent {
    pub fn detected(fp: Fingerprint, path: impl Into<String>, line: usize) -> Self {
        Self {
            ts: Utc::now(),
            event: HistoryEventKind::Detected,
            fingerprint: fp,
            commit: None,
            path: Some(path.into()),
            line: Some(line),
            extra: Value::Null,
        }
    }

    pub fn verified_live(fp: Fingerprint, provider: &str, method: &str) -> Self {
        Self {
            ts: Utc::now(),
            event: HistoryEventKind::VerifiedLive,
            fingerprint: fp,
            commit: None,
            path: None,
            line: None,
            extra: serde_json::json!({ "provider": provider, "method": method }),
        }
    }
}

/// Append one event to `path`. Creates the file if missing.
pub fn append_event(path: &Path, event: &HistoryEvent) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| crate::Error::io(path, e))?;
    let line = serde_json::to_string(event)?;
    writeln!(file, "{line}").map_err(|e| crate::Error::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn append_creates_then_appends() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("h.jsonl");
        let fp = Fingerprint("abc".into());
        append_event(&path, &HistoryEvent::detected(fp.clone(), "a.rb", 1)).unwrap();
        append_event(&path, &HistoryEvent::verified_live(fp, "aws", "sts")).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
    }
}
