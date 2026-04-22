//! Convenience loaders for the fixture catalog.

use std::path::Path;

use crate::Result;

use super::{Catalog, VerifyingKey};

/// Load and parse a catalog file from disk. Verifies the signature if
/// `key` is provided.
pub fn load_from_path(path: &Path, key: Option<&VerifyingKey>) -> Result<Catalog> {
    Catalog::load(path, key)
}

/// Parse a catalog from a string (used by tests and by the bundled
/// snapshot).
pub fn load_from_str(raw: &str, key: Option<&VerifyingKey>) -> Result<Catalog> {
    Catalog::parse(raw, key)
}
