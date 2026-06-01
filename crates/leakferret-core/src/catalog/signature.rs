//! Ed25519 signature support for the fixture catalog.
//!
//! Canonical payload format: the serialised JSON of the `CatalogFile`
//! with `signature` cleared. We then `serde_json` it with sorted keys
//! and feed the bytes to `ed25519-dalek` for sign / verify.

use base64::Engine;
use ed25519_dalek::{Signer, Verifier};

pub use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::Error;

use super::CatalogFile;

/// Base64-encoded raw 32 bytes of the project's Ed25519 public key,
/// embedded at compile time.
///
/// Catalog files loaded via `leakferret catalog refresh`, and any
/// previously-refreshed copy on disk, must be signed with the matching
/// private key or loading them fails. The bundled snapshot compiled into
/// the binary is loaded with `expected_key = None` (it is part of the
/// trusted build artefact), so this does not affect default scans.
///
/// The matching private key is kept offline and as the catalog repo's CI
/// signing secret; see `leakferret-catalog/tools/sign/README.md` for the
/// key-management procedure. To rotate, generate a new keypair, replace the
/// bytes below (and the expected value in the test), and re-sign every
/// published catalog file.
pub const EMBEDDED_PUBLIC_KEY: Option<&str> = Some("VxGTRy8eoWkb6k9s7noAbtSybHve4mGYymhV7y70cRI=");

/// Decode [`EMBEDDED_PUBLIC_KEY`] into a [`VerifyingKey`].
///
/// Returns `None` if no public key is embedded (current state — see the
/// constant's doc comment for the rationale). Returns `Some(key)` once
/// the project keypair is generated and the constant is populated.
///
/// # Panics
///
/// Does not panic. A malformed embedded key surfaces as `Err`, but the
/// happy path for "no key embedded yet" returns `Ok(None)`.
pub fn embedded_verifying_key() -> crate::Result<Option<VerifyingKey>> {
    let Some(encoded) = EMBEDDED_PUBLIC_KEY else {
        return Ok(None);
    };
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| Error::CatalogSignature(format!("embedded key base64: {e}")))?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        Error::CatalogSignature(format!("embedded key must be 32 bytes, got {}", raw.len()))
    })?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|e| Error::CatalogSignature(format!("embedded key parse: {e}")))?;
    Ok(Some(key))
}

/// Verify `signature` over the canonical bytes of `file` using `key`.
/// Returns Ok on valid signature, Err otherwise. The caller decides
/// whether to bubble up or warn.
pub fn verify_signature(
    file: &CatalogFile,
    signature_b64: &str,
    key: &VerifyingKey,
) -> crate::Result<()> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| Error::CatalogSignature(format!("base64 decode: {e}")))?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::CatalogSignature(format!("signature parse: {e}")))?;

    let canonical = canonical_payload(file)?;
    key.verify(canonical.as_bytes(), &signature)
        .map_err(|e| Error::CatalogSignature(format!("verify: {e}")))
}

/// Sign `file` with `key` and return the base64 signature. Used by
/// the catalog-signing tool in `leakferret-catalog`.
pub fn sign_catalog(file: &CatalogFile, key: &SigningKey) -> crate::Result<String> {
    let canonical = canonical_payload(file)?;
    let signature = key.sign(canonical.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
}

/// Produce the canonical JSON over which signatures are computed:
/// the file with `signature` cleared, serialised with deterministic
/// key order.
fn canonical_payload(file: &CatalogFile) -> crate::Result<String> {
    let mut clone = file.clone();
    clone.signature = None;
    // `serde_json::to_string` is not stable across key orderings for
    // arbitrary maps but `CatalogFile` is a struct with fixed field
    // order, so the output is deterministic.
    Ok(serde_json::to_string(&clone)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::{rngs::OsRng, RngCore};

    fn random_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    use super::super::{CatalogEntry, CatalogVerdict, MatchStrategy, TrustLevel};

    fn sample_file() -> CatalogFile {
        CatalogFile {
            schema_version: 1,
            catalog_version: "2026.05.27".into(),
            license: "CC-BY-SA-4.0".into(),
            signature: None,
            signing_key_id: Some("test".into()),
            entries: vec![CatalogEntry {
                id: "stripe.test.docs".into(),
                kind: "stripe_test_key".into(),
                matcher: MatchStrategy::Exact {
                    value: "sk_test_4eC39HqLyjWDarjtT1zdp7dc".into(),
                },
                source: "https://stripe.com/docs/testing".into(),
                source_checked_at: Some("2026-04-01".into()),
                rationale: Some("Stripe canonical test key".into()),
                trust: TrustLevel::VendorPublished,
                verdict: CatalogVerdict::Fixture,
            }],
        }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = random_signing_key();
        let file = sample_file();
        let sig = sign_catalog(&file, &key).unwrap();
        verify_signature(&file, &sig, &key.verifying_key()).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key_a = random_signing_key();
        let key_b = random_signing_key();
        let file = sample_file();
        let sig = sign_catalog(&file, &key_a).unwrap();
        assert!(verify_signature(&file, &sig, &key_b.verifying_key()).is_err());
    }

    #[test]
    fn embedded_public_key_is_valid_and_pinned() {
        // The project's signing keypair is generated. The embedded constant
        // must decode to a valid 32-byte Ed25519 verifying key. If the key is
        // rotated, update the expected value here to match the new public key.
        const EXPECTED: &str = "VxGTRy8eoWkb6k9s7noAbtSybHve4mGYymhV7y70cRI=";
        assert_eq!(EMBEDDED_PUBLIC_KEY, Some(EXPECTED));
        let key = embedded_verifying_key().expect("embedded key must decode");
        assert!(key.is_some(), "embedded key must produce a verifying key");
    }
}
