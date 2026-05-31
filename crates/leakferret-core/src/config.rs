//! Engine-level configuration shared across CLI flags, env vars, and
//! the `.leakferret.toml` config file.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level engine configuration. Wraps everything `Engine` needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    /// Root path to scan. Defaults to current dir.
    pub root: PathBuf,
    /// Extra glob patterns to exclude in addition to `.gitignore`.
    pub extra_excludes: Vec<String>,
    /// If `Some`, only scan files whose absolute paths are in this set.
    pub only_paths: Option<Vec<PathBuf>>,
    /// Maximum file size to scan (bytes). Files larger than this are
    /// skipped — almost never source code at that point.
    pub max_file_bytes: u64,
    /// Lines of context to capture either side of each finding.
    pub context_lines: usize,
    /// Verification strategy.
    pub verify_mode: VerifyMode,
    /// Per-verifier timeout (seconds).
    pub verifier_timeout_secs: u64,
    /// Rewriter target backend.
    pub rewrite_backend: RewriteBackend,
    /// Path to baseline file (relative to root). `None` disables.
    pub baseline_path: Option<PathBuf>,
    /// Path to history file (relative to root). `None` disables.
    pub history_path: Option<PathBuf>,
    /// Path to custom fixture catalog. `None` uses the bundled one.
    pub catalog_path: Option<PathBuf>,
    /// Whether to include FIXTURE-classified findings in output.
    pub show_fixtures: bool,
    /// Maximum concurrent verifier HTTP calls.
    pub verifier_concurrency: usize,
    /// Persist the baseline, history, and salt to the repo. Off by default
    /// so a plain `scan`/`verify` never writes files into the user's tree;
    /// the baseline is read-only (for diffing) unless this is set.
    pub update_baseline: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            extra_excludes: Vec::new(),
            only_paths: None,
            max_file_bytes: 2 * 1024 * 1024,
            context_lines: 3,
            verify_mode: VerifyMode::default(),
            verifier_timeout_secs: 10,
            rewrite_backend: RewriteBackend::default(),
            baseline_path: Some(PathBuf::from(".leakferret-baseline.json")),
            history_path: Some(PathBuf::from(".leakferret-history.jsonl")),
            catalog_path: None,
            show_fixtures: false,
            verifier_concurrency: 8,
            update_baseline: false,
        }
    }
}

/// Verification strategy applied to candidate findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerifyMode {
    /// Skip verifiers entirely (fastest; same as gitleaks).
    None,
    /// Run verifiers but never fail the run on a verifier error.
    #[default]
    BestEffort,
    /// Only emit findings that verified live. Trufflehog `--only-verified`.
    OnlyVerified,
    /// Verify and fail the run on *any* secret that ever verified
    /// (current OR historical via baseline).
    EverVerified,
}

/// Secret-manager target for rewrite seed commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RewriteBackend {
    #[default]
    Env,
    Vault,
    Doppler,
    AwsSecretsManager,
    Infisical,
}
