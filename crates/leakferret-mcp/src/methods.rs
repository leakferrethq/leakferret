//! Tool + prompt handlers.

use std::path::PathBuf;

use serde_json::{json, Value};

use leakferret_core::{
    classifier::{Classifier, OfflineClassifier, SYSTEM_PROMPT},
    finding::{FindingView, Severity, Verdict},
    Engine, EngineConfig, Finding, Rewriter,
};

use crate::protocol::{codes, Prompt, Resource, Response, Tool};

pub const TOOLS: &[Tool] = &[
    Tool {
        name: "scan_repository",
        description: "Walks a directory tree and returns regex-pre-filter candidate secrets. Verdict is unknown — call classify_candidates next, or use the prompt at prompts/get name=classify to have the host model classify in-conversation.",
        input_schema: Value::Null, // populated lazily below
    },
    Tool {
        name: "classify_candidates",
        description: "Apply offline heuristic classification to candidates from scan_repository. Returns the same candidates with verdict / reason / confidence filled in.",
        input_schema: Value::Null,
    },
    Tool {
        name: "propose_rewrite",
        description: "For a finding classified REAL, propose a code edit that swaps the hardcoded secret for an env-var lookup, plus a .env.example entry and secret-manager seed commands. Never stores or transmits the secret value.",
        input_schema: Value::Null,
    },
    Tool {
        name: "verify_finding",
        description: "Run the matching provider verifier (live HTTP call). The secret value goes from this host directly to the provider; we never proxy it.",
        input_schema: Value::Null,
    },
    Tool {
        name: "baseline_diff",
        description: "Diff scan findings against the repo's baseline. Returns four slices: `new` (scan findings absent from baseline), `ever_verified` (baseline entries present in this scan that ever verified live), `rotated` (baseline entries with status Rotated that are present), and `stats` (counts). Lets an agent answer 'is anything new?' without walking the whole baseline.",
        input_schema: Value::Null,
    },
];

pub const PROMPTS: &[Prompt] = &[Prompt {
    name: "classify",
    description: "System prompt for classifying candidate secrets as REAL / FIXTURE / UNKNOWN.",
}];

pub const RESOURCES: &[Resource] = &[
    Resource {
        uri: "leakferret://secret-types",
        name: "Detectable secret types",
        description: "Every secret pattern leakferret can detect, with its id, human description, and default severity.",
        mime_type: "application/json",
    },
    Resource {
        uri: "leakferret://verifiers",
        name: "Live-verification providers",
        description: "Providers leakferret can confirm a key against with a single live API call, plus the trufflehog fallback.",
        mime_type: "application/json",
    },
];

/// Serve a resource body for `resources/read`. Both resources are static,
/// derived from the built-in registries, and contain no secret material.
pub fn read_resource(id: Option<Value>, params: Value) -> Response {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let body = match uri {
        "leakferret://secret-types" => {
            let registry = leakferret_core::patterns::PatternRegistry::builtin();
            let types: Vec<Value> = registry
                .iter()
                .map(|p| {
                    json!({
                        "id": p.id,
                        "description": p.description,
                        "severity": p.severity,
                    })
                })
                .collect();
            let count = types.len();
            serde_json::to_string_pretty(&json!({ "count": count, "secret_types": types }))
        }
        "leakferret://verifiers" => {
            let registry = leakferret_core::verifier::VerifierRegistry::builtin();
            let providers = registry.providers();
            let count = providers.len();
            serde_json::to_string_pretty(&json!({ "count": count, "providers": providers }))
        }
        other => {
            return Response::error(
                id,
                codes::INVALID_PARAMS,
                format!("unknown resource: {other}"),
            );
        }
    };

    match body {
        Ok(text) => Response::ok(
            id,
            json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": text,
                }],
            }),
        ),
        Err(e) => Response::error(id, codes::INTERNAL, format!("{e:#}")),
    }
}

pub async fn call_tool(id: Option<Value>, params: Value) -> Response {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);

    let result = match name {
        "scan_repository" => tool_scan(&args).await,
        "classify_candidates" => tool_classify(&args),
        "propose_rewrite" => tool_rewrite(&args),
        "verify_finding" => tool_verify(&args).await,
        "baseline_diff" => tool_baseline_diff(&args).await,
        other => {
            return Response::error(id, codes::INVALID_PARAMS, format!("unknown tool: {other}"));
        }
    };

    match result {
        Ok(value) => Response::ok(
            id,
            json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&value).unwrap_or_default(),
                }],
            }),
        ),
        Err(e) => Response::error(id, codes::INTERNAL, format!("{e:#}")),
    }
}

pub fn get_prompt(id: Option<Value>, params: Value) -> Response {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if name != "classify" {
        return Response::error(id, codes::INVALID_PARAMS, format!("unknown prompt: {name}"));
    }
    Response::ok(
        id,
        json!({
            "description": PROMPTS[0].description,
            "messages": [{
                "role": "user",
                "content": { "type": "text", "text": SYSTEM_PROMPT },
            }]
        }),
    )
}

// --- Tool implementations ---

async fn tool_scan(args: &Value) -> anyhow::Result<Value> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing 'path'"))?;
    let exclude: Vec<String> = args
        .get("exclude")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let cfg = EngineConfig {
        root: PathBuf::from(path),
        extra_excludes: exclude,
        // No verification on this path — scan_repository is the cheap one.
        verify_mode: leakferret_core::VerifyMode::None,
        baseline_path: None,
        history_path: None,
        ..EngineConfig::default()
    };
    let engine = Engine::new(cfg.clone());
    let report = engine.scan_path(&cfg.root).await?;
    let views: Vec<FindingView> = report.findings.iter().map(Into::into).collect();
    Ok(json!({ "candidates": views }))
}

fn tool_classify(args: &Value) -> anyhow::Result<Value> {
    let candidates = args
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("missing 'candidates'"))?;
    let mut findings: Vec<Finding> = candidates.iter().map(hydrate_finding).collect();
    let empty = leakferret_core::Catalog::empty();
    OfflineClassifier::new(&empty).classify(&mut findings);
    let views: Vec<FindingView> = findings.iter().map(Into::into).collect();
    Ok(json!({ "candidates": views }))
}

fn tool_rewrite(args: &Value) -> anyhow::Result<Value> {
    let finding = args
        .get("finding")
        .ok_or_else(|| anyhow::anyhow!("missing 'finding'"))?;
    let mut f = hydrate_finding(finding);
    f.verdict = Verdict::Real;
    let r = Rewriter::default();
    match r.propose(&f) {
        Some(rep) => Ok(serde_json::to_value(rep)?),
        None => Ok(json!({ "error": "unsupported language or no safe rewrite available" })),
    }
}

async fn tool_verify(args: &Value) -> anyhow::Result<Value> {
    let finding = args
        .get("finding")
        .ok_or_else(|| anyhow::anyhow!("missing 'finding'"))?;
    let f = hydrate_finding(finding);
    let registry = leakferret_core::verifier::VerifierRegistry::builtin();
    let verifiers = registry.for_pattern(&f.pattern);
    if verifiers.is_empty() {
        return Ok(json!({ "status": "unverified", "reason": "no verifier for pattern" }));
    }
    let ctx = leakferret_core::verifier::VerifierContext::new(10)?;
    let outcome = verifiers[0].verify(&f, &ctx).await;
    Ok(serde_json::to_value(outcome)?)
}

/// `baseline_diff` returns a *slice* of the baseline + scan state so
/// an agent can decide "should I block this commit?" without walking
/// every fingerprint. Shape:
///
/// ```json
/// {
///   "new":           [FindingView, ...],
///   "ever_verified": [BaselineEntry, ...],
///   "rotated":       [BaselineEntry, ...],
///   "stats": {
///     "total_in_scan":        12,
///     "total_in_baseline":    34,
///     "new_count":             3,
///     "ever_verified_count":   1,
///     "rotated_count":         0
///   }
/// }
/// ```
async fn tool_baseline_diff(args: &Value) -> anyhow::Result<Value> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing 'path'"))?;
    let cfg = EngineConfig {
        root: PathBuf::from(path),
        ..EngineConfig::default()
    };
    let engine = Engine::new(cfg.clone());
    let report = engine.scan_path(&cfg.root).await?;

    let scan_fingerprints: std::collections::HashSet<String> = report
        .findings
        .iter()
        .filter_map(|f| f.fingerprint.as_ref().map(|fp| fp.as_str().to_string()))
        .collect();

    // `new`: scan findings whose fingerprint is NOT in the baseline.
    let baseline_keys: std::collections::HashSet<&str> = report
        .baseline
        .as_ref()
        .map(|b| b.entries.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let new_findings: Vec<FindingView> = report
        .findings
        .iter()
        .filter(|f| match &f.fingerprint {
            Some(fp) => !baseline_keys.contains(fp.as_str()),
            None => true,
        })
        .map(Into::into)
        .collect();

    // `ever_verified` + `rotated`: baseline entries present in this
    // scan that match those criteria.
    let (ever_verified, rotated): (
        Vec<&leakferret_core::baseline::BaselineEntry>,
        Vec<&leakferret_core::baseline::BaselineEntry>,
    ) = report
        .baseline
        .as_ref()
        .map(|b| {
            let mut ever = Vec::new();
            let mut rot = Vec::new();
            for (key, entry) in &b.entries {
                if !scan_fingerprints.contains(key) {
                    continue;
                }
                if entry.ever_verified {
                    ever.push(entry);
                }
                if matches!(
                    entry.status,
                    leakferret_core::baseline::BaselineStatus::Rotated
                ) {
                    rot.push(entry);
                }
            }
            (ever, rot)
        })
        .unwrap_or_default();

    let total_in_baseline = report.baseline.as_ref().map_or(0, |b| b.entries.len());

    Ok(json!({
        "new": new_findings,
        "ever_verified": ever_verified,
        "rotated": rotated,
        "stats": {
            "total_in_scan": report.findings.len(),
            "total_in_baseline": total_in_baseline,
            "new_count": new_findings.len(),
            "ever_verified_count": ever_verified.len(),
            "rotated_count": rotated.len(),
        }
    }))
}

fn hydrate_finding(value: &Value) -> Finding {
    let path = value
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let line = value.get("line").and_then(Value::as_u64).unwrap_or(1) as usize;
    let column = value.get("column").and_then(Value::as_u64).unwrap_or(1) as usize;
    let r#match = value
        .get("match")
        .or_else(|| value.get("match_redacted"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let pattern = value
        .get("pattern")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let severity_str = value
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let severity = match severity_str {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Unknown,
    };
    let context: Vec<String> = value
        .get("context")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let verdict = value
        .get("verdict")
        .and_then(Value::as_str)
        .map(Verdict::parse_loose)
        .unwrap_or(Verdict::Unknown);

    Finding {
        path: PathBuf::from(path),
        line,
        column,
        r#match,
        pattern,
        severity,
        context,
        verdict,
        reason: value
            .get("reason")
            .and_then(Value::as_str)
            .map(String::from),
        confidence: value
            .get("confidence")
            .and_then(Value::as_f64)
            .map(|v| v as f32),
        verification: None,
        fingerprint: None,
        replacement: None,
        git_commit: None,
        git_commit_subject: None,
    }
}
