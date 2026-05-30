//! Thin wrapper over the `ignore` crate. Returns the list of file
//! paths to scan after applying gitignore, hidden-file, and binary-
//! extension filters.

use std::collections::HashSet;
use std::path::PathBuf;

use ignore::{overrides::OverrideBuilder, WalkBuilder};

use crate::Result;

/// File extensions we *do* scan. Anything else (binaries, images,
/// archives) is skipped without even opening the file.
pub const DEFAULT_INCLUDE_EXT: &[&str] = &[
    "rb",
    "erb",
    "rake",
    "py",
    "pyi",
    "pyx",
    "js",
    "mjs",
    "cjs",
    "jsx",
    "ts",
    "tsx",
    "vue",
    "svelte",
    "go",
    "java",
    "kt",
    "kts",
    "scala",
    "rs",
    "ex",
    "exs",
    "ml",
    "mli",
    "clj",
    "cljs",
    "cljc",
    "php",
    "swift",
    "sh",
    "bash",
    "zsh",
    "fish",
    "pl",
    "pm",
    "lua",
    "c",
    "cc",
    "cpp",
    "h",
    "hpp",
    "cxx",
    "yml",
    "yaml",
    "toml",
    "json",
    "json5",
    "ini",
    "conf",
    "properties",
    "xml",
    "tf",
    "tfvars",
    "hcl",
    "nomad",
    "md",
    "mdx",
    "txt",
    "rst",
    "gradle",
    "groovy",
    "dockerfile",
    "containerfile",
];

/// Directories always excluded from the walk. These hold agent/tool
/// state — notably Claude Code worktrees under `.claude/`, which are
/// full repo checkouts — so scanning them would duplicate the project.
const DEFAULT_EXCLUDE_DIRS: &[&str] = &[".claude/", "**/.claude/"];

/// Top-level walker configuration. Carried by [`crate::Scanner`].
#[derive(Debug, Clone)]
pub struct WalkConfig {
    pub root: PathBuf,
    pub extra_excludes: Vec<String>,
    pub max_file_bytes: u64,
    pub only_paths: Option<Vec<PathBuf>>,
}

/// Walk the configured root and return an absolute-path list of files
/// that survived gitignore + extension + size filters.
pub fn walk(cfg: &WalkConfig) -> Result<Vec<PathBuf>> {
    let only: Option<HashSet<PathBuf>> =
        cfg.only_paths.as_ref().map(|v| v.iter().cloned().collect());

    let include_ext: HashSet<&str> = DEFAULT_INCLUDE_EXT.iter().copied().collect();

    let mut overrides = OverrideBuilder::new(&cfg.root);
    // Built-in excludes for agent/tool state. `.claude/` holds Claude
    // Code worktrees — full checkouts of the repo — so scanning it means
    // scanning the project N times over. Pruning the directory is both a
    // correctness fix (no duplicate findings) and the dominant perf win
    // on machines that use agent worktrees.
    for pat in DEFAULT_EXCLUDE_DIRS {
        overrides
            .add(&format!("!{pat}"))
            .map_err(|e| crate::Error::Other(format!("default exclude {pat:?}: {e}")))?;
    }
    for pat in &cfg.extra_excludes {
        // `!` prefix in `ignore::overrides` *exclude*s a glob.
        overrides
            .add(&format!("!{pat}"))
            .map_err(|e| crate::Error::Other(format!("invalid exclude glob {pat:?}: {e}")))?;
    }
    let overrides = overrides
        .build()
        .map_err(|e| crate::Error::Other(format!("override build failed: {e}")))?;

    let walker = WalkBuilder::new(&cfg.root)
        .standard_filters(true) // .gitignore, .ignore, hidden
        .hidden(false) // scan dotfiles (.env, .npmrc, ...) — secrets hide there
        .require_git(false) // honour .gitignore even outside a git repo
        .git_global(true)
        .git_exclude(true)
        .git_ignore(true)
        .overrides(overrides)
        .follow_links(false)
        .build();

    let mut out = Vec::with_capacity(1024);
    for entry in walker {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.into_path();

        if let Some(only) = &only {
            if !only.contains(&path) {
                continue;
            }
        }

        // .env / .env.local / .env.production etc are always scanned.
        let basename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if basename.starts_with(".env") {
            if !exceeds_size(&path, cfg.max_file_bytes) {
                out.push(path);
            }
            continue;
        }

        // Filter by extension.
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase);
        let Some(ext) = ext else { continue };
        if !include_ext.contains(ext.as_str()) {
            continue;
        }
        if exceeds_size(&path, cfg.max_file_bytes) {
            continue;
        }
        out.push(path);
    }
    Ok(out)
}

fn exceeds_size(path: &std::path::Path, limit: u64) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() > limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn respects_extension_allowlist() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.rb"), "x").unwrap();
        std::fs::write(tmp.path().join("b.png"), b"\x89PNG").unwrap();
        let cfg = WalkConfig {
            root: tmp.path().to_path_buf(),
            extra_excludes: vec![],
            max_file_bytes: 1024,
            only_paths: None,
        };
        let files = walk(&cfg).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("a.rb"));
    }

    #[test]
    fn respects_gitignore() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(".gitignore"), "ignored.rb\n").unwrap();
        std::fs::write(tmp.path().join("kept.rb"), "x").unwrap();
        std::fs::write(tmp.path().join("ignored.rb"), "x").unwrap();
        let cfg = WalkConfig {
            root: tmp.path().to_path_buf(),
            extra_excludes: vec![],
            max_file_bytes: 1024,
            only_paths: None,
        };
        let files = walk(&cfg).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("kept.rb"));
    }

    #[test]
    fn includes_dotenv_even_without_extension() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(".env.local"), "x").unwrap();
        let cfg = WalkConfig {
            root: tmp.path().to_path_buf(),
            extra_excludes: vec![],
            max_file_bytes: 1024,
            only_paths: None,
        };
        let files = walk(&cfg).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn excludes_dot_claude_worktrees_by_default() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("real.rb"), "x").unwrap();
        let wt = tmp.path().join(".claude/worktrees/copy");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join("dup.rb"), "x").unwrap();
        let cfg = WalkConfig {
            root: tmp.path().to_path_buf(),
            extra_excludes: vec![],
            max_file_bytes: 1024,
            only_paths: None,
        };
        let files = walk(&cfg).unwrap();
        assert_eq!(files.len(), 1, "the .claude worktree copy must be skipped");
        assert!(files[0].ends_with("real.rb"));
    }
}
