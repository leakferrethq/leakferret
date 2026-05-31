//! Privacy invariant: the raw secret value must never appear in any
//! buffer that leaves the machine or lands in a committed file. That
//! covers reporter output (JSON / SARIF / pretty), the host-LLM prompt,
//! the persisted baseline and history files, fingerprints, the
//! MCP-facing `FindingView`, and a whole-`Finding` serialization.
//!
//! The test plants a sentinel secret, runs it through every public
//! serializer, and asserts both the literal value and a unique middle
//! token (which the first-4/last-4 redaction can never expose) are
//! absent from the output.

use std::path::PathBuf;

use leakferret_core::{
    classifier::HostPrompt,
    finding::{Finding, FindingView, Fingerprint, Severity, Verdict},
    reporter::{JsonReporter, PrettyReporter, Reporter, SarifReporter},
    Engine, EngineConfig, ReporterFormat, Rewriter, VerifyMode,
};

/// Sentinel secret shaped like an AWS access key (`AKIA` + 16 chars) so
/// the live scanner matches it. First-4 = `AKIA`, last-4 = `4XYZ`; the
/// unique core token `NEVERLEAK` sits in the middle, where the
/// first-4/last-4 redaction can never reveal it.
const RAW_SECRET: &str = "AKIANEVERLEAK1234XYZ";

/// A substring guaranteed absent from any redacted form. A stronger
/// guard than the full value alone: it also catches partial leaks.
const CORE_TOKEN: &str = "NEVERLEAK";

/// Assert a rendered buffer contains neither the raw secret nor its
/// unique core token.
fn assert_clean(label: &str, buf: &str) {
    assert!(
        !buf.contains(RAW_SECRET),
        "{label}: raw secret leaked into output:\n{buf}"
    );
    assert!(
        !buf.contains(CORE_TOKEN),
        "{label}: secret core token leaked into output:\n{buf}"
    );
}

/// The worst case for leakage: a `Real` finding whose raw secret lives in
/// both the match and a context line, with a rewriter proposal attached
/// (so `Replacement` and the whole `Finding` both get serialized).
fn real_finding_with_replacement() -> Finding {
    let mut f = Finding {
        path: PathBuf::from("app/config.rb"),
        line: 2,
        column: 1,
        r#match: RAW_SECRET.to_string(),
        pattern: "aws_access_key".to_string(),
        severity: Severity::High,
        context: vec![
            "# credentials".to_string(),
            format!("AWS_ACCESS_KEY = '{RAW_SECRET}'"),
            "# end".to_string(),
        ],
        verdict: Verdict::Real,
        reason: Some("under app/, live key structure".to_string()),
        confidence: Some(0.93),
        verification: None,
        fingerprint: Some(Fingerprint::compute(
            RAW_SECRET,
            b"privacy-test-salt-0000000000",
        )),
        replacement: None,
        git_commit: None,
        git_commit_subject: None,
    };
    f.replacement = Rewriter::default().propose(&f);
    assert!(
        f.replacement.is_some(),
        "precondition: rewriter should propose a replacement for this finding"
    );
    f
}

#[test]
fn every_serializer_redacts_the_raw_secret() {
    let findings = vec![real_finding_with_replacement()];

    // 1. JSON reporter (FindingView).
    let mut json = Vec::new();
    JsonReporter.emit(&findings, &mut json).unwrap();
    let json = String::from_utf8(json).unwrap();
    assert_clean("json reporter", &json);
    // Positive control: the redacted preview *is* present, proving the
    // finding was actually serialized (guards against an empty-buffer
    // false pass).
    assert!(
        json.contains("AKIA...4XYZ"),
        "json should contain the redacted preview"
    );

    // 2. SARIF reporter.
    let mut sarif = Vec::new();
    SarifReporter.emit(&findings, &mut sarif).unwrap();
    assert_clean("sarif reporter", &String::from_utf8(sarif).unwrap());

    // 3. Pretty reporter — prints the old_line/new_line diff verbatim.
    let mut pretty = Vec::new();
    PrettyReporter::default()
        .emit(&findings, &mut pretty)
        .unwrap();
    assert_clean("pretty reporter", &String::from_utf8(pretty).unwrap());

    // 4. FindingView serialization (the MCP-facing projection).
    let view = FindingView::from(&findings[0]);
    assert_clean("finding view", &serde_json::to_string(&view).unwrap());

    // 5. Host-LLM classification prompt.
    let prompt = HostPrompt::for_findings(&findings);
    assert_clean("host prompt", &serde_json::to_string(&prompt).unwrap());

    // 6. Whole-`Finding` serialization — `match` is skip_serializing and
    //    `replacement.old_line` is redacted, so even this must be clean.
    assert_clean(
        "whole finding",
        &serde_json::to_string(&findings[0]).unwrap(),
    );

    // 7. The `Replacement` on its own (returned directly by the MCP
    //    `propose_rewrite` tool).
    let rep = findings[0].replacement.as_ref().unwrap();
    assert_clean("replacement", &serde_json::to_string(rep).unwrap());

    // 8. Fingerprint — an HMAC, must not echo its input in any form.
    let fp = Fingerprint::compute(RAW_SECRET, b"another-salt-00000000000000");
    assert_clean("fingerprint", &serde_json::to_string(&fp).unwrap());
    assert_clean("fingerprint str", fp.as_str());
}

#[tokio::test]
async fn end_to_end_pipeline_never_persists_the_raw_secret() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::write(
        root.join("app/config.rb"),
        format!("AWS_ACCESS_KEY = '{RAW_SECRET}'\n"),
    )
    .unwrap();

    let cfg = EngineConfig {
        root: root.to_path_buf(),
        // No verifiers — this test must never touch the network.
        verify_mode: VerifyMode::None,
        baseline_path: Some(PathBuf::from(".leakferret-baseline.json")),
        history_path: Some(PathBuf::from(".leakferret-history.jsonl")),
        // Exercise the persisted baseline/history write path so the privacy
        // assertions below cover it.
        update_baseline: true,
        ..EngineConfig::default()
    };
    let engine = Engine::new(cfg);
    let report = engine.scan_path(root).await.unwrap();

    assert!(
        !report.findings.is_empty(),
        "scanner should find the planted secret"
    );

    // Reporters over the real pipeline output (fixtures included).
    for (label, fmt) in [
        ("json", ReporterFormat::Json),
        ("sarif", ReporterFormat::Sarif),
        ("pretty", ReporterFormat::Pretty),
    ] {
        let mut buf = Vec::new();
        leakferret_core::reporter::emit(fmt, &report.findings, &mut buf, true).unwrap();
        assert_clean(&format!("{label} (e2e)"), &String::from_utf8(buf).unwrap());
    }

    // Persisted artifacts that may be committed or uploaded to CI.
    let baseline = std::fs::read_to_string(root.join(".leakferret-baseline.json")).unwrap();
    assert_clean("baseline file", &baseline);
    if let Ok(history) = std::fs::read_to_string(root.join(".leakferret-history.jsonl")) {
        assert_clean("history file", &history);
    }

    // The one place the raw secret is allowed to exist is the planted
    // source file itself — confirm it's genuinely there, so the test
    // isn't trivially passing on absence everywhere.
    let source = std::fs::read_to_string(root.join("app/config.rb")).unwrap();
    assert!(
        source.contains(RAW_SECRET),
        "planted source file must still hold the secret"
    );
}
