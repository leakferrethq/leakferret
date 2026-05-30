//! Orchestrator. Wires scanner → catalog → classifier → verifier →
//! rewriter → reporter together and emits a [`ScanReport`].

use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::baseline::{
    self, Baseline, BaselineEntry, BaselineExposure, BaselineStatus, HistoryEvent,
};
use crate::catalog::{embedded_verifying_key, Catalog};
use crate::classifier::{Classifier, OfflineClassifier};
use crate::config::{EngineConfig, VerifyMode};
use crate::finding::fingerprint::load_or_create_salt;
use crate::finding::{Finding, Fingerprint};
use crate::patterns::PatternRegistry;
use crate::rewriter::Rewriter;
use crate::scanner::{GitHistoryScanner, Scanner};
use crate::verifier::{VerifierContext, VerifierRegistry};
use crate::Result;

/// Top-level orchestrator. Owns the registries and the loaded catalog.
#[derive(Debug)]
pub struct Engine {
    pub config: EngineConfig,
    pub patterns: PatternRegistry,
    pub catalog: Catalog,
    pub verifiers: VerifierRegistry,
}

impl Engine {
    /// Build with the default registries (built-in patterns, built-in
    /// verifiers, resolved catalog). For tests and quick starts.
    ///
    /// The catalog is resolved via [`Self::load_catalog_chain`]:
    /// refreshed copy → user override → bundled snapshot. A failure to
    /// resolve any of those falls back to [`Catalog::empty`] rather
    /// than panicking — a missing catalog must not block scanning.
    pub fn new(config: EngineConfig) -> Self {
        let catalog = Self::load_catalog_chain(&config).unwrap_or_else(|err| {
            tracing::warn!("catalog chain failed to load ({err}); falling back to empty catalog");
            Catalog::empty()
        });
        Self {
            config,
            patterns: PatternRegistry::builtin(),
            catalog,
            verifiers: VerifierRegistry::builtin(),
        }
    }

    /// Resolve the catalog to use for this engine instance, in order:
    ///
    /// 1. Refreshed copy under `~/.config/leakferret/catalog/<latest>.json`
    ///    (written by `leakferret catalog refresh`).
    /// 2. `cfg.catalog_path` if the user explicitly overrode it.
    /// 3. The bundled snapshot.
    ///
    /// Catalogs loaded from the refresh directory must verify against
    /// the embedded public key when one is configured (see
    /// [`crate::catalog::EMBEDDED_PUBLIC_KEY`]). The bundled snapshot is
    /// `include_str!`'d into the binary at build time — a vendored copy of
    /// the `leakferret-catalog` repo (CC-BY-SA-4.0) — and is trusted as-is,
    /// since tampering with it means tampering with the binary itself.
    pub fn load_catalog_chain(cfg: &EngineConfig) -> Result<Catalog> {
        let embedded = embedded_verifying_key()?;

        // 1. Refreshed copy.
        if let Some(latest) = refresh_catalog_latest_path() {
            if latest.exists() {
                tracing::debug!(?latest, "loading refreshed catalog");
                return Catalog::load(&latest, embedded.as_ref());
            }
        }

        // 2. User override.
        if let Some(custom) = &cfg.catalog_path {
            tracing::debug!(?custom, "loading user-configured catalog");
            // User-supplied path is trusted as-is (e.g. local dev catalog
            // pulled from git): no signature enforced unless they wired
            // one in themselves.
            return Catalog::load(custom, None);
        }

        // 3. Bundled snapshot, compiled into the binary. No signature
        //    check — it is part of the trusted binary. Fall back to an
        //    empty catalog only if the vendored copy fails to parse.
        Ok(
            Catalog::parse(include_str!("../catalog/snapshot.json"), None).unwrap_or_else(|err| {
                tracing::warn!("bundled catalog failed to parse ({err}); using empty catalog");
                Catalog::empty()
            }),
        )
    }

    /// Build with an explicit catalog (e.g. signed snapshot loaded by
    /// the CLI).
    pub fn with_catalog(mut self, catalog: Catalog) -> Self {
        self.catalog = catalog;
        self
    }

    /// Replace the pattern registry (e.g. add user-defined patterns).
    pub fn with_patterns(mut self, patterns: PatternRegistry) -> Self {
        self.patterns = patterns;
        self
    }

    /// Replace the verifier registry.
    pub fn with_verifiers(mut self, verifiers: VerifierRegistry) -> Self {
        self.verifiers = verifiers;
        self
    }

    /// Run the full pipeline against a path, return a [`ScanReport`].
    pub async fn scan_path(&self, path: impl AsRef<Path>) -> Result<ScanReport> {
        let path = path.as_ref();
        let mut cfg = self.config.clone();
        cfg.root = path.to_path_buf();

        // 1. Scan.
        let scanner = Scanner::new(&cfg, &self.patterns);
        let mut findings = scanner.scan()?;

        // 2. Fingerprint (uses per-repo salt under cfg.root).
        let salt = load_or_create_salt(&cfg.root)?;
        for f in &mut findings {
            f.fingerprint = Some(Fingerprint::compute(&f.r#match, &salt));
        }

        // 3. Verify (if mode allows).
        if cfg.verify_mode != VerifyMode::None {
            let ctx = build_verifier_context(&cfg, &findings)?;
            self.verifiers
                .verify_all(&mut findings, &ctx, cfg.verifier_concurrency)
                .await;
        }

        // 4. Classify (offline). Host-LLM classification is driven by
        //    the MCP server, not the engine.
        let classifier = OfflineClassifier::new(&self.catalog);
        classifier.classify(&mut findings);

        // 5. Rewriter — only for Real findings; non-fatal if it fails.
        let rewriter = Rewriter::new(cfg.rewrite_backend);
        for f in &mut findings {
            if f.is_real() {
                f.replacement = rewriter.propose(f);
            }
        }

        // 6. Baseline update.
        let baseline = if let Some(bp) = &cfg.baseline_path {
            let bp_full = cfg.root.join(bp);
            let mut baseline = baseline::load_or_init(&bp_full)?;
            update_baseline(&mut baseline, &findings);
            baseline::save(&bp_full, &baseline)?;
            Some(baseline)
        } else {
            None
        };

        // 7. History events.
        if let Some(hp) = &cfg.history_path {
            let hp_full = cfg.root.join(hp);
            for f in &findings {
                if let Some(fp) = &f.fingerprint {
                    let evt =
                        HistoryEvent::detected(fp.clone(), f.path.display().to_string(), f.line);
                    let _ = baseline::append_event(&hp_full, &evt);
                    if f.is_verified() {
                        if let Some(v) = &f.verification {
                            let evt = HistoryEvent::verified_live(
                                fp.clone(),
                                v.provider(),
                                "live_api_call",
                            );
                            let _ = baseline::append_event(&hp_full, &evt);
                        }
                    }
                }
            }
        }

        Ok(ScanReport {
            findings,
            baseline,
            scanned_root: cfg.root,
        })
    }

    /// Run the full pipeline against a git repository's *history*
    /// instead of the working tree. The `since` / `until` revisions are
    /// passed to [`GitHistoryScanner`]; pass `None` for either to use
    /// the default (root commit / `HEAD`).
    ///
    /// Each returned [`Finding`] carries `git_commit` + `git_commit_subject`
    /// metadata identifying the commit it was introduced in.
    ///
    /// Unlike [`Engine::scan_path`], baseline + history files are NOT
    /// updated by this entry point — history scans are intended as a
    /// read-only audit pass over past commits, and writing them into the
    /// baseline would corrupt the working-tree baseline accounting.
    pub async fn scan_git_history(
        &self,
        repo: impl AsRef<Path>,
        since: Option<String>,
        until: Option<String>,
        max_depth: Option<usize>,
    ) -> Result<ScanReport> {
        let repo = repo.as_ref();
        let cfg = self.config.clone();

        // 1. Scan history.
        let mut scanner = GitHistoryScanner::new(repo, &self.patterns)
            .context_lines(cfg.context_lines)
            .max_blob_bytes(cfg.max_file_bytes);
        if let Some(s) = since {
            scanner = scanner.since(s);
        }
        if let Some(u) = until {
            scanner = scanner.until(u);
        }
        if let Some(n) = max_depth {
            scanner = scanner.max_depth(n);
        }
        let mut findings = scanner.scan().await?;

        // 2. Fingerprint.
        let salt = load_or_create_salt(repo)?;
        for f in &mut findings {
            f.fingerprint = Some(Fingerprint::compute(&f.r#match, &salt));
        }

        // 3. Verify (if mode allows). Note: history secrets that verify
        //    live today are *currently active* secrets accidentally
        //    introduced via the working tree at some prior point — the
        //    most valuable signal a CI buyer can get.
        if cfg.verify_mode != VerifyMode::None {
            let ctx = build_verifier_context(&cfg, &findings)?;
            self.verifiers
                .verify_all(&mut findings, &ctx, cfg.verifier_concurrency)
                .await;
        }

        // 4. Classify (offline).
        let classifier = OfflineClassifier::new(&self.catalog);
        classifier.classify(&mut findings);

        // 5. No rewriter, no baseline update — see the doc comment.

        Ok(ScanReport {
            findings,
            baseline: None,
            scanned_root: repo.to_path_buf(),
        })
    }
}

/// Result of a full scan.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<Baseline>,
    pub scanned_root: std::path::PathBuf,
}

impl ScanReport {
    pub fn real_count(&self) -> usize {
        self.findings.iter().filter(|f| f.is_real()).count()
    }
    pub fn verified_count(&self) -> usize {
        self.findings.iter().filter(|f| f.is_verified()).count()
    }
    pub fn ci_exit_code(&self, mode: VerifyMode) -> i32 {
        match mode {
            VerifyMode::None | VerifyMode::BestEffort => crate::reporter::exit_code(&self.findings),
            VerifyMode::OnlyVerified => i32::from(self.verified_count() > 0),
            VerifyMode::EverVerified => {
                let any_ever = self
                    .baseline
                    .as_ref()
                    .is_some_and(|b| b.entries.values().any(|e| e.ever_verified));
                i32::from(any_ever || self.verified_count() > 0)
            }
        }
    }
}

/// Directory under the user's config dir where
/// `leakferret catalog refresh` persists fetched catalogs.
fn refresh_catalog_dir() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("leakferret").join("catalog"))
}

/// Path of the locally-refreshed "latest" catalog file, if any.
///
/// Resolution: read `<refresh_dir>/latest.json` (a pointer written by
/// `catalog refresh`) and dereference its `current` field to
/// `<refresh_dir>/<current>.json`. If the pointer is missing or
/// malformed, return `None` — the chain falls through to the next tier.
fn refresh_catalog_latest_path() -> Option<std::path::PathBuf> {
    let dir = refresh_catalog_dir()?;
    let pointer = dir.join("latest.json");
    let raw = std::fs::read_to_string(&pointer).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let current = parsed.get("current")?.as_str()?;
    Some(dir.join(format!("{current}.json")))
}

/// Build a `VerifierContext` and pre-load any paired secrets that
/// scanner findings hint at (e.g. an `AWS_SECRET_ACCESS_KEY` finding
/// supplies the secret needed by the AWS verifier).
fn build_verifier_context(cfg: &EngineConfig, findings: &[Finding]) -> Result<VerifierContext> {
    let mut ctx = VerifierContext::new(cfg.verifier_timeout_secs)?;
    let mut pair: HashMap<String, String> = HashMap::new();
    for f in findings {
        if f.pattern == "aws_secret_key" {
            pair.insert("AWS_SECRET_ACCESS_KEY".into(), f.r#match.clone());
        }
        if f.pattern == "aws_session_token" {
            pair.insert("AWS_SESSION_TOKEN".into(), f.r#match.clone());
        }
    }
    // Also honour environment vars (useful in CI without secrets in source).
    for (k, v) in std::env::vars() {
        if matches!(k.as_str(), "AWS_SECRET_ACCESS_KEY" | "AWS_SESSION_TOKEN") {
            pair.entry(k).or_insert(v);
        }
    }
    ctx.paired_secrets = pair;
    Ok(ctx)
}

fn update_baseline(baseline: &mut Baseline, findings: &[Finding]) {
    let now = Utc::now();
    for f in findings {
        let Some(fp) = &f.fingerprint else { continue };
        let key = fp.as_str().to_string();
        let key_preview = f.redacted_match();
        let kind = f.pattern.clone();
        let verified = f.is_verified();

        let entry = baseline
            .entries
            .entry(key)
            .or_insert_with(|| BaselineEntry {
                fingerprint: fp.clone(),
                kind: kind.clone(),
                key_preview,
                status: BaselineStatus::Active,
                first_seen_at: now,
                last_verified_at: None,
                verification_attempts: 0,
                ever_verified: false,
                first_path: Some(f.path.clone()),
                first_line: Some(f.line),
                exposure: BaselineExposure::default(),
            });
        entry.verification_attempts = entry.verification_attempts.saturating_add(1);
        if verified {
            entry.ever_verified = true;
            entry.last_verified_at = Some(now);
            entry.status = BaselineStatus::Active;
        } else if entry.ever_verified {
            entry.status = BaselineStatus::Rotated;
        } else if f.is_fixture() {
            entry.status = BaselineStatus::Fixture;
        }
    }
}
