# leakferret-core

The engine. Library crate exposing the scanner, fixture catalog,
classifier, verifier registry, rewriter, reporters, and baseline store
that `leakferret-cli` and `leakferret-mcp` wrap.

Add it to your own Rust project to embed the same pipeline:

```toml
[dependencies]
leakferret-core = "0.1"
```

See the crate docs (`cargo doc --open -p leakferret-core`) for the
public API. The public surface is intentionally small — `Engine`,
`Finding`, `Verdict`, `Severity`, `Catalog`, `Baseline`, and the trait
abstractions for `Classifier`, `Verifier`, `Reporter`, `Rewriter`.
