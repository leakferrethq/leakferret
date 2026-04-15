//! HMAC-SHA256 fingerprint with a per-repo salt. Used by the baseline
//! and history stores to identify a secret across runs *without*
//! storing the raw value.
//!
//! Why HMAC and not plain SHA?
//!   A raw SHA-256 of a 20-char AWS key is rainbow-tableable in
//!   minutes by anyone with a leaked baseline. HMAC with a per-repo
//!   secret salt makes the fingerprint useless outside the repo it
//!   was generated for.

use std::path::Path;

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

const SALT_FILE: &str = ".leakferret-salt";
const SALT_LEN: usize = 32;

/// Stable per-repo fingerprint of a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fingerprint(pub String);

impl Fingerprint {
    /// Compute an HMAC-SHA256 fingerprint of `value` using the given
    /// `salt`. Salt should be 32 random bytes from
    /// [`load_or_create_salt`].
    pub fn compute(value: &str, salt: &[u8]) -> Self {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key length");
        mac.update(value.as_bytes());
        let bytes = mac.finalize().into_bytes();
        // URL-safe base64 without padding — short, copy-pasteable into JSON keys.
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        Self(encoded)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Read the per-repo salt from `<root>/.leakferret-salt`. If the
/// file doesn't exist, generate 32 random bytes and persist them.
/// The file is added to `.gitignore` by the CLI on baseline init.
pub fn load_or_create_salt(root: &Path) -> crate::Result<Vec<u8>> {
    let salt_path = root.join(SALT_FILE);
    if salt_path.exists() {
        let data = std::fs::read(&salt_path).map_err(|e| crate::Error::io(&salt_path, e))?;
        let trimmed: Vec<u8> = data
            .iter()
            .filter(|b| !b.is_ascii_whitespace())
            .copied()
            .collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&trimmed)
            .map_err(|e| crate::Error::Other(format!("salt file is not valid base64: {e}")))?;
        if bytes.len() < 16 {
            return Err(crate::Error::Other(format!(
                "salt file too short ({} bytes); expected >= 16",
                bytes.len()
            )));
        }
        return Ok(bytes);
    }

    let mut salt = vec![0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&salt);
    std::fs::write(&salt_path, format!("{encoded}\n"))
        .map_err(|e| crate::Error::io(&salt_path, e))?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn same_value_same_salt_same_fingerprint() {
        let salt = b"deadbeefcafebabe1234567890abcdef";
        let a = Fingerprint::compute("AKIAIOSFODNN7EXAMPLE", salt);
        let b = Fingerprint::compute("AKIAIOSFODNN7EXAMPLE", salt);
        assert_eq!(a, b);
    }

    #[test]
    fn different_salt_different_fingerprint() {
        let a = Fingerprint::compute(
            "AKIAIOSFODNN7EXAMPLE",
            b"saltA00000000000000000000000000000",
        );
        let b = Fingerprint::compute(
            "AKIAIOSFODNN7EXAMPLE",
            b"saltB00000000000000000000000000000",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn salt_file_is_created_then_reused() {
        let tmp = TempDir::new().unwrap();
        let s1 = load_or_create_salt(tmp.path()).unwrap();
        let s2 = load_or_create_salt(tmp.path()).unwrap();
        assert_eq!(s1, s2);
        assert!(tmp.path().join(SALT_FILE).exists());
    }
}
