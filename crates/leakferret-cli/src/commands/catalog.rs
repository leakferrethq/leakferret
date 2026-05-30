//! `leakferret catalog` — load and inspect the fixture catalog.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};

use leakferret_core::catalog::{
    embedded_verifying_key, verify_signature, CatalogFile, VerifyingKey,
};
use leakferret_core::{Catalog, Engine, EngineConfig};

/// Default URL the `refresh` subcommand fetches from when `--url` is
/// not supplied.
pub const DEFAULT_CATALOG_URL: &str = "https://catalog.leakferret.com/latest.json";

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Sub,
}

#[derive(Debug, Subcommand)]
pub enum Sub {
    /// Print catalog metadata (version, entry count, license).
    Info {
        /// Catalog JSON file. Defaults to bundled snapshot.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// List all entries as JSON.
    List {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Test a value against the catalog and print the verdict if any.
    Test {
        value: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Fetch a fresh catalog from the CDN, verify its Ed25519
    /// signature against the embedded public key (or `--verify-key`),
    /// and persist it under `~/.config/leakferret/catalog/`.
    Refresh {
        /// Catalog URL. Defaults to [`DEFAULT_CATALOG_URL`].
        #[arg(long)]
        url: Option<String>,
        /// Base64-encoded 32-byte Ed25519 public key. Overrides the
        /// embedded key. Useful for staging environments.
        #[arg(long)]
        verify_key: Option<String>,
        /// Path to write the verified catalog to. Defaults to
        /// `~/.config/leakferret/catalog/<version>.json` and updates
        /// `latest.json` to point at the new file.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

pub async fn run(args: Args) -> Result<i32> {
    match args.cmd {
        Sub::Info { file } => info(file.as_deref()),
        Sub::List { file } => list(file.as_deref()),
        Sub::Test { value, file } => test(&value, file.as_deref()),
        Sub::Refresh {
            url,
            verify_key,
            output,
        } => refresh(url, verify_key, output).await,
    }
}

fn load(file: Option<&std::path::Path>) -> Result<Catalog> {
    match file {
        // An explicit --file is loaded verbatim (no chain, no signature
        // check beyond what Catalog::load applies).
        Some(p) => Catalog::load(p, None).context("load catalog"),
        // No --file: resolve the same chain the engine uses — a
        // refreshed local snapshot if one exists, otherwise the copy
        // bundled into the binary. This is why `catalog info` reports
        // populated entries out of the box.
        None => Engine::load_catalog_chain(&EngineConfig::default())
            .context("load bundled catalog chain"),
    }
}

fn info(file: Option<&std::path::Path>) -> Result<i32> {
    let c = load(file)?;
    println!("catalog_version: {}", c.file.catalog_version);
    println!("schema_version:  {}", c.file.schema_version);
    println!("license:         {}", c.file.license);
    println!("entries:         {}", c.file.entries.len());
    Ok(0)
}

fn list(file: Option<&std::path::Path>) -> Result<i32> {
    let c = load(file)?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &c.file.entries)?;
    println!();
    Ok(0)
}

fn test(value: &str, file: Option<&std::path::Path>) -> Result<i32> {
    let c = load(file)?;
    match c.lookup(value) {
        Some((verdict, id)) => {
            println!("hit: {id} → {verdict:?}");
            Ok(0)
        }
        None => {
            println!("no catalog entry matched");
            Ok(1)
        }
    }
}

/// `leakferret catalog refresh` entry point.
async fn refresh(
    url: Option<String>,
    verify_key: Option<String>,
    output: Option<PathBuf>,
) -> Result<i32> {
    let url = url.unwrap_or_else(|| DEFAULT_CATALOG_URL.to_string());
    let key = resolve_verify_key(verify_key.as_deref())?;

    let body = fetch_catalog(&url).await?;
    let parsed = parse_and_verify(&body, key.as_ref())
        .with_context(|| format!("verify catalog from {url}"))?;

    let dest = resolve_output_path(output, &parsed.catalog_version)?;
    write_catalog(&dest, &body, &parsed.catalog_version)?;

    println!(
        "refreshed: version={} entries={} -> {}",
        parsed.catalog_version,
        parsed.entries.len(),
        dest.display()
    );
    Ok(0)
}

/// Resolve which Ed25519 public key, if any, to verify the fetched
/// catalog against. `--verify-key` overrides the embedded key.
fn resolve_verify_key(override_b64: Option<&str>) -> Result<Option<VerifyingKey>> {
    if let Some(encoded) = override_b64 {
        return Ok(Some(decode_verify_key(encoded)?));
    }
    embedded_verifying_key().map_err(|e| anyhow!("embedded public key invalid: {e}"))
}

fn decode_verify_key(encoded: &str) -> Result<VerifyingKey> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("--verify-key is not valid base64")?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("--verify-key must decode to 32 bytes (got {})", raw.len()))?;
    VerifyingKey::from_bytes(&bytes).context("--verify-key is not a valid Ed25519 public key")
}

async fn fetch_catalog(url: &str) -> Result<String> {
    let resp = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let status = resp.status();
    if !status.is_success() {
        bail!("catalog fetch failed: {url} returned HTTP {status}");
    }
    resp.text()
        .await
        .with_context(|| format!("read response body from {url}"))
}

/// Parse the body as a `CatalogFile` and, if a key is configured,
/// verify the signature. Returns the parsed file so the caller can
/// surface version + entry count without re-parsing.
fn parse_and_verify(body: &str, key: Option<&VerifyingKey>) -> Result<CatalogFile> {
    let file: CatalogFile =
        serde_json::from_str(body).context("catalog payload is not valid JSON")?;
    if let Some(key) = key {
        let sig = file.signature.as_deref().ok_or_else(|| {
            anyhow!("catalog payload has no signature but a verify key is configured")
        })?;
        verify_signature(&file, sig, key)
            .map_err(|e| anyhow!("catalog signature verification failed: {e}"))?;
    }
    Ok(file)
}

/// Resolve the on-disk destination for a refreshed catalog.
///
/// Default: `<config_dir>/leakferret/catalog/<version>.json`.
fn resolve_output_path(explicit: Option<PathBuf>, version: &str) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let base =
        dirs::config_dir().ok_or_else(|| anyhow!("could not determine user config directory"))?;
    Ok(base
        .join("leakferret")
        .join("catalog")
        .join(format!("{version}.json")))
}

/// Write the verified catalog body to `dest` and, when `dest` lives in
/// the canonical refresh directory, update `latest.json` to point at
/// the new file.
fn write_catalog(dest: &Path, body: &str, version: &str) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(dest, body).with_context(|| format!("write {}", dest.display()))?;

    // If we landed under the canonical refresh dir, update the pointer
    // so `Engine::load_catalog_chain` picks the new file up.
    if let Some(canonical) = dirs::config_dir().map(|d| d.join("leakferret").join("catalog")) {
        if dest.parent() == Some(canonical.as_path()) {
            let pointer = canonical.join("latest.json");
            let payload = serde_json::json!({
                "current": version,
                "schema_version": 1,
            });
            std::fs::write(&pointer, serde_json::to_vec_pretty(&payload)?)
                .with_context(|| format!("write {}", pointer.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use leakferret_core::catalog::CatalogFile as CoreCatalogFile;
    use leakferret_core::catalog::{
        sign_catalog, CatalogEntry, CatalogVerdict, MatchStrategy, TrustLevel,
    };
    use rand::{rngs::OsRng, RngCore};
    use tempfile::tempdir;

    fn random_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn sample_unsigned() -> CoreCatalogFile {
        CoreCatalogFile {
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

    fn signed_body(key: &SigningKey) -> String {
        let mut file = sample_unsigned();
        let sig = sign_catalog(&file, key).unwrap();
        file.signature = Some(sig);
        serde_json::to_string(&file).unwrap()
    }

    fn b64_pub(key: &SigningKey) -> String {
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
    }

    #[test]
    fn default_load_resolves_the_bundled_catalog() {
        // Without --file, `catalog info`/`test` must fall through the
        // engine chain to the snapshot compiled into the binary, not an
        // empty catalog. Guards the regression where documented public
        // keys were reported as unknown on a fresh install.
        let c = load(None).expect("default catalog should resolve");
        assert!(
            !c.file.entries.is_empty(),
            "bundled catalog must be populated"
        );
        assert!(c.lookup("sk_test_4eC39HqLyjWDarjtT1zdp7dc").is_some());
    }

    #[tokio::test]
    async fn refresh_accepts_valid_signed_catalog() {
        let key = random_signing_key();
        let body = signed_body(&key);

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/latest.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let tmp = tempdir().unwrap();
        let out = tmp.path().join("fetched.json");

        let code = refresh(
            Some(format!("{}/latest.json", server.url())),
            Some(b64_pub(&key)),
            Some(out.clone()),
        )
        .await
        .unwrap();

        mock.assert_async().await;
        assert_eq!(code, 0);
        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(written, body);
    }

    #[tokio::test]
    async fn refresh_rejects_tampered_catalog() {
        let key = random_signing_key();
        let mut tampered: CoreCatalogFile = serde_json::from_str(&signed_body(&key)).unwrap();
        // Mutate an entry AFTER signing — signature no longer matches.
        tampered.entries[0].source = "https://attacker.example/swap".into();
        let body = serde_json::to_string(&tampered).unwrap();

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/latest.json")
            .with_status(200)
            .with_body(&body)
            .create_async()
            .await;

        let tmp = tempdir().unwrap();
        let out = tmp.path().join("fetched.json");

        let err = refresh(
            Some(format!("{}/latest.json", server.url())),
            Some(b64_pub(&key)),
            Some(out.clone()),
        )
        .await
        .unwrap_err();

        mock.assert_async().await;
        assert!(
            format!("{err:#}").contains("signature"),
            "expected signature error, got: {err:#}"
        );
        // Crucially: a bad payload must NOT be cached.
        assert!(!out.exists(), "tampered payload must not be persisted");
    }

    #[tokio::test]
    async fn refresh_reports_http_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/missing.json")
            .with_status(404)
            .with_body("not found")
            .create_async()
            .await;

        let tmp = tempdir().unwrap();
        let out = tmp.path().join("never.json");

        let err = refresh(
            Some(format!("{}/missing.json", server.url())),
            None,
            Some(out.clone()),
        )
        .await
        .unwrap_err();

        mock.assert_async().await;
        let msg = format!("{err:#}");
        assert!(msg.contains("404"), "expected 404 in error, got: {msg}");
        assert!(!out.exists(), "404 payload must not be persisted");
    }
}
