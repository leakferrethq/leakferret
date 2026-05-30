//! # leakferret-core
//!
//! The engine behind the `leakferret` CLI, MCP server, and IDE
//! integrations. This crate is the single source of truth for:
//!
//! * file walking + regex pre-filter (`scanner`)
//! * fixture catalog with Ed25519-signed updates (`catalog`)
//! * offline + host-LLM classification (`classifier`)
//! * provider-verified live secrets (`verifier`)
//! * language-aware rewriter (`rewriter`)
//! * pretty / JSON / SARIF reporters (`reporter`)
//! * HMAC-fingerprinted baseline + append-only history (`baseline`)
//!
//! All of these are exposed as composable building blocks, then
//! wrapped by the orchestrator in [`engine::Engine`].
//!
//! ## Quick start
//!
//! ```no_run
//! use leakferret_core::{Engine, EngineConfig};
//!
//! # async fn run() -> leakferret_core::Result<()> {
//! let engine = Engine::new(EngineConfig::default());
//! let report = engine.scan_path(".").await?;
//! println!("{} findings", report.findings.len());
//! # Ok(()) }
//! ```
//!
//! ## Design rule
//!
//! The full secret value lives only on disk. Every public API redacts
//! to first-4-plus-last-4 chars via [`Finding::redacted_match`]. Output
//! reporters, MCP responses, and classifier prompts all consume the
//! redacted form. Fingerprints are HMAC-SHA256 with a per-repo salt;
//! the catalog never receives raw values either.

#![doc(html_root_url = "https://docs.rs/leakferret-core/0.1.0")]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod baseline;
pub mod catalog;
pub mod classifier;
pub mod config;
pub mod engine;
pub mod error;
pub mod finding;
pub mod patterns;
pub mod reporter;
pub mod rewriter;
pub mod scanner;
pub mod verifier;

pub use crate::{
    baseline::{Baseline, BaselineEntry, BaselineStatus, HistoryEvent, HistoryEventKind},
    catalog::{Catalog, CatalogEntry, CatalogVerdict},
    classifier::{Classifier, ClassifyMode, OfflineClassifier},
    config::{EngineConfig, RewriteBackend, VerifyMode},
    engine::{Engine, ScanReport},
    error::{Error, Result},
    finding::{Finding, Fingerprint, Severity, Verdict},
    patterns::{Pattern, PatternId, PatternRegistry},
    reporter::{Reporter, ReporterFormat},
    rewriter::{Language, Replacement, Rewriter},
    scanner::{GitHistoryScanner, ScanProgress, Scanner},
    verifier::{VerificationOutcome, Verifier, VerifierRegistry},
};

/// Crate version string (compile-time from Cargo).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name.
pub const NAME: &str = env!("CARGO_PKG_NAME");
