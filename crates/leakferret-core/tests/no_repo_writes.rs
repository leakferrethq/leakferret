//! A plain scan/verify must NEVER write baseline/history/salt files into the
//! user's repo. Those are created only with `update_baseline = true`.

use leakferret_core::{Engine, EngineConfig, VerifyMode};
use tempfile::TempDir;

const FILES: [&str; 3] = [
    ".leakferret-baseline.json",
    ".leakferret-history.jsonl",
    ".leakferret-salt",
];

fn repo_with_secret() -> TempDir {
    let tmp = TempDir::new().unwrap();
    std::fs::write(
        tmp.path().join("config.rb"),
        "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
    )
    .unwrap();
    tmp
}

#[tokio::test]
async fn plain_verify_writes_nothing_to_the_repo() {
    let tmp = repo_with_secret();
    let root = tmp.path();
    let cfg = EngineConfig {
        root: root.to_path_buf(),
        verify_mode: VerifyMode::None, // no network
        // update_baseline defaults to false
        ..EngineConfig::default()
    };
    Engine::new(cfg).scan_path(root).await.unwrap();

    for f in FILES {
        assert!(
            !root.join(f).exists(),
            "{f} must NOT be created by a plain verify"
        );
    }
}

#[tokio::test]
async fn update_baseline_records_into_the_repo() {
    let tmp = repo_with_secret();
    let root = tmp.path();
    let cfg = EngineConfig {
        root: root.to_path_buf(),
        verify_mode: VerifyMode::None,
        update_baseline: true,
        ..EngineConfig::default()
    };
    Engine::new(cfg).scan_path(root).await.unwrap();

    assert!(root.join(".leakferret-baseline.json").exists());
    assert!(root.join(".leakferret-salt").exists());
}
