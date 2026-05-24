# leakferret

[![CI](https://github.com/leakferrethq/leakferret/actions/workflows/ci.yml/badge.svg)](https://github.com/leakferrethq/leakferret/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)

**Context-aware secret detection with provider-verified findings,
fingerprinted historical baseline, and machine-applied rewrites.**
MCP-native so AI agents can call it before they commit.

```
                  scan      → regex pre-filter      (gitleaks-class noise)
                  ↓
                  catalog   → known-fixture lookup  (deterministic NO answers)
                  ↓
                  verify    → live provider call    (trufflehog-class accuracy)
                  ↓
                  classify  → host LLM / offline    (closes the gap on UNKNOWN)
                  ↓
                  rewrite   → ENV.fetch in-place    (agent-applicable diff)
                  ↓
                  baseline  → HMAC fingerprint log  (catches ever-verified leaks)
```

## What it is, in 4 facts

1. **Same regex pre-filter as gitleaks**, written in Rust, single static binary.
2. **Same provider-verified findings as trufflehog**: AWS / GitHub / GitLab /
   Stripe / OpenAI / Anthropic / Slack (more landing). Secret never leaves
   your machine — the call goes from you to the provider.
3. **Versioned fixture catalog** so Stripe test keys / AWS canary patterns /
   RFC examples / JWT.io examples get a deterministic FIXTURE verdict in
   microseconds — without verification round-trips. Trufflehog will mark
   these "verified live" because they *are* live test keys; we don't.
4. **Per-repo HMAC-fingerprinted baseline** that catches *ever-verified*
   leaks. A key that was real on Tuesday and got rotated Friday is still a
   historical leak; we keep it in the gate. Trufflehog can't see this.

## Distribution

| Surface | Install | Repo |
|---|---|---|
| Native binary | GitHub Releases (`leakferret-*.tar.gz`) | this repo |
| Rust crate   | `cargo install leakferret-cli` | this repo |
| Ruby gem     | `gem install leakferret`       | [leakferret-ruby](https://github.com/leakferrethq/leakferret-ruby) |
| Go module    | `go install github.com/leakferrethq/leakferret-go/cmd/leakferret@latest` | [leakferret-go](https://github.com/leakferrethq/leakferret-go) |
| npm CLI      | `npm i -D @leakferret/cli`     | [leakferret-npm](https://github.com/leakferrethq/leakferret-npm) |
| npm MCP      | `npx @leakferret/mcp`          | [leakferret-npm](https://github.com/leakferrethq/leakferret-npm) |
| GH Action    | `uses: leakferrethq/leakferret-action@v1` | [leakferret-action](https://github.com/leakferrethq/leakferret-action) |
| Fixture catalog | shipped with binary; updateable from CDN | [leakferret-catalog](https://github.com/leakferrethq/leakferret-catalog) |

The Ruby / Go / npm packages are thin wrappers that download the same native
binary on install (same pattern as `ruff`, `biome`, `esbuild`). One engine,
six entry points, identical semantics.

## CLI

```bash
leakferret scan .                            # regex pre-filter, no verifier
leakferret verify .                          # + offline classify + verifier
leakferret verify . --only-verified          # trufflehog-mode
leakferret verify . --verify-mode ever-verified   # fails on historical leaks
leakferret rewrite . --apply                 # write ENV.fetch in place
leakferret rewrite . --backend doppler       # emit Doppler seed cmds
leakferret baseline init                     # start the per-repo ledger
leakferret baseline show
leakferret catalog test "sk_test_4eC39…"     # deterministic NO answer
leakferret mcp                               # MCP server on stdio
```

Output formats: `--format pretty|json|sarif`. SARIF is what GitHub Code
Scanning ingests; the GH Action wrapper uploads it for you.

## MCP

```json
{
  "mcpServers": {
    "leakferret": {
      "command": "leakferret",
      "args": ["mcp"]
    }
  }
}
```

Tools exposed: `scan_repository`, `classify_candidates`, `propose_rewrite`,
`verify_finding`, `baseline_diff`. Prompt: `classify` (the host-LLM system
prompt so an agent can classify candidates inline using the model it
already has).

## Repo layout

```
leakferret/                       # this repo — Rust workspace
├── crates/
│   ├── leakferret-core/          # library: scanner, catalog, classifier,
│   │                              # verifier, rewriter, reporters, baseline
│   ├── leakferret-cli/           # bin: leakferret
│   └── leakferret-mcp/           # lib + server: MCP over stdio
├── catalog/                       # bundled snapshot of leakferret-catalog
├── legacy-ruby/                   # archived 0.0.x Ruby gem (reference)
└── .github/workflows/             # CI + cargo-dist release
```

## Local development

Linux / macOS:

```bash
git clone https://github.com/leakferrethq/leakferret
cd leakferret
cargo build --release
./target/release/leakferret scan .
```

Windows: install [Visual Studio 2022 Build Tools] with the "Desktop
development with C++" workload (for MSVC's `link.exe`) **or** install
MSYS2 + MinGW-w64 then `rustup default 1.95.0-x86_64-pc-windows-gnu`.
The Rust GNU toolchain on Windows needs MSYS2's `dlltool.exe` for
linking; pure rustup install isn't sufficient.

[Visual Studio 2022 Build Tools]: https://visualstudio.microsoft.com/downloads/?q=build+tools

## License

MIT for the engine, CLI, MCP, and all language wrappers. CC-BY-SA-4.0
for the fixture catalog data.

The 0.0.x Ruby gem is archived under `legacy-ruby/` and is no longer
the shipping artefact — it's preserved as the working spec for the
Rust port.
