use serde::{Deserialize, Serialize};

use super::Language;

/// The proposed code edit + sidecar `.env.example` entry +
/// secret-manager seed commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Replacement {
    pub env_var: String,
    pub language: Language,
    /// The original line, with the secret value redacted to its
    /// first-4/last-4 preview. The raw value is never stored here — see
    /// `Rewriter::propose`. Informational only; `--apply` rewrites the
    /// real file directly.
    pub old_line: String,
    pub new_line: String,
    pub env_example_line: String,
    pub seed_commands: Vec<String>,
}
