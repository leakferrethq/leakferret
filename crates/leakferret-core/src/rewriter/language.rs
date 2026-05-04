//! File-extension → language detection + the env-var call template
//! per language.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Ruby,
    JavaScript,
    TypeScript,
    Python,
    Yaml,
    Json,
    Env,
    Shell,
    Go,
    Java,
    Kotlin,
    Scala,
    Rust,
    Php,
}

impl Language {
    /// Detect from path. Returns `None` for unrecognised extensions.
    pub fn detect(path: &Path) -> Option<Self> {
        // Dotenv files first: `Path` reports `.env.local`'s extension as
        // "local", so the basename check has to precede extension matching.
        let basename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if basename.starts_with(".env") {
            return Some(Self::Env);
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase)?;
        match ext.as_str() {
            "rb" | "erb" | "rake" => Some(Self::Ruby),
            "js" | "mjs" | "cjs" | "jsx" | "vue" | "svelte" => Some(Self::JavaScript),
            "ts" | "tsx" => Some(Self::TypeScript),
            "py" | "pyi" | "pyx" => Some(Self::Python),
            "yml" | "yaml" => Some(Self::Yaml),
            "json" | "json5" => Some(Self::Json),
            "sh" | "bash" | "zsh" | "fish" => Some(Self::Shell),
            "go" => Some(Self::Go),
            "java" => Some(Self::Java),
            "kt" | "kts" => Some(Self::Kotlin),
            "scala" => Some(Self::Scala),
            "rs" => Some(Self::Rust),
            "php" => Some(Self::Php),
            _ => None,
        }
    }

    /// Whether we can safely rewrite for this language.
    pub fn is_supported(self) -> bool {
        // JSON and .env have no env-call form, but we still want them
        // detected so the engine can flag them; just no rewrite.
        !matches!(self, Self::Json | Self::Env)
    }

    /// Env-var call template — what we substitute the secret with.
    pub fn env_call(self, name: &str) -> Option<String> {
        Some(match self {
            Self::Ruby => format!("ENV.fetch('{name}')"),
            Self::JavaScript | Self::TypeScript => format!("process.env.{name}"),
            Self::Python => format!("os.environ['{name}']"),
            Self::Yaml | Self::Shell => format!("${{{name}}}"),
            Self::Go => format!("os.Getenv(\"{name}\")"),
            Self::Java | Self::Kotlin | Self::Scala => format!("System.getenv(\"{name}\")"),
            Self::Rust => format!("std::env::var(\"{name}\").expect(\"missing {name}\")"),
            Self::Php => format!("getenv('{name}')"),
            Self::Json | Self::Env => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_ruby() {
        assert_eq!(
            Language::detect(&PathBuf::from("a.rb")),
            Some(Language::Ruby)
        );
    }

    #[test]
    fn detects_dotenv() {
        assert_eq!(
            Language::detect(&PathBuf::from(".env.local")),
            Some(Language::Env)
        );
    }

    #[test]
    fn returns_none_for_unknown_ext() {
        assert_eq!(Language::detect(&PathBuf::from("a.xyz")), None);
    }

    #[test]
    fn rust_env_call_uses_std_env() {
        assert!(Language::Rust
            .env_call("X")
            .unwrap()
            .contains("std::env::var"));
    }
}
