//! The binary must ship with the fixture catalog compiled in, so it
//! deterministically suppresses documented-public test credentials out of
//! the box (no CDN refresh required).

use leakferret_core::{Engine, EngineConfig};

#[test]
fn bundled_catalog_is_populated_and_matches_known_fixtures() {
    let catalog =
        Engine::load_catalog_chain(&EngineConfig::default()).expect("catalog chain should resolve");

    assert!(
        !catalog.file.entries.is_empty(),
        "the binary should ship with a non-empty fixture catalog",
    );
    assert!(
        catalog.lookup("sk_test_4eC39HqLyjWDarjtT1zdp7dc").is_some(),
        "Stripe's documented test key should be a catalog hit",
    );
    assert!(
        catalog.lookup("AKIAIOSFODNN7EXAMPLE").is_some(),
        "AWS's documented example access key should be a catalog hit",
    );
}
