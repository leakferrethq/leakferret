# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.9] - 2026-06-03

### Added
- `leakferret org <owner>`: scan every public repository owned by a GitHub user
  or organization in one command. Lists the owner's repos via the GitHub API,
  shallow-clones each, runs the scan engine, and emits one aggregated report
  with each finding's path prefixed by `owner/repo/`. Forks and archived repos
  are skipped by default (`--include-forks`, `--include-archived`); `--token`
  (or `GITHUB_TOKEN`) raises the API rate limit; `--max-repos` caps the run.

## [0.1.8] - 2026-06-03

### Added
- MCP server now exposes **resources**: `leakferret://secret-types` (every
  detectable pattern with id, description, and severity) and
  `leakferret://verifiers` (the live-verification providers). Both are
  read-only context derived from the built-in registries and contain no secret
  material. The `initialize` handshake advertises the `resources` capability
  alongside `tools` and `prompts`.

## [0.1.7] - 2026-06-03

### Added
- Detection for ~28 more secret types (**60+ total**): Hugging Face, Groq,
  Perplexity, Replicate, GitLab runner tokens, Google OAuth secrets, Atlassian,
  Figma, RubyGems, Shopify, Square (incl. the modern `EAAA…` form), Databricks,
  Vault, Doppler, Linear, Notion, Postman, PlanetScale, Supabase, Grafana,
  Tailscale, New Relic, Sentry, Dropbox, Flutterwave, Airtable, Brevo,
  Mailchimp, Discord, and Telegram.
- Live provider verification for 10 more providers (**~25 total**): Hugging
  Face, Groq, Replicate, Notion, Postman, Figma, Linear, Square, Shopify, and
  Databricks. Each confirmed against the real provider API.
- Context host-extraction: tenant-scoped tokens (Shopify, Databricks) are
  verified by pulling the shop domain / workspace host out of the surrounding
  context, the way trufflehog does.

### Fixed
- Databricks verification uses the permission-free `scim/v2/Me` endpoint, so a
  live-but-scoped token is no longer mis-reported as dead.

## [0.1.6] - 2026-06-01

### Fixed

- Correct the 0.1.5 single-file fix. 0.1.5 changed the recorded path but broke
  the `root.join(path)` invariant the rewriter relies on, so
  `leakferret rewrite src/config.js` errored. A single-file path argument is now
  rooted at the working directory (keeping e.g. `src/config.js` as the relative
  path) with the file added to `only_paths`, so scan, classify and rewrite all
  agree whether you pass `.` or a file — and the rewriter resolves the file.

## [0.1.5] - 2026-06-01

### Fixed

- Scanning a single file directly (e.g. `leakferret rewrite src/config.js`)
  recorded an empty path, dropping the directory context the app-path classifier
  relies on. The same key then classified REAL via `scan .` but UNKNOWN via the
  file path, so `rewrite <file>` silently rewrote nothing. The recorded path now
  keeps the file's parent (e.g. `src/config.js`) regardless of how it is passed.

## [0.1.4] - 2026-06-01

### Added

- `--fail-on <none|any|real|verified>` on `scan` and `verify`. `--fail-on any`
  exits non-zero on any non-fixture finding, which makes
  `leakferret verify . --verify-mode none --fail-on any` a fully offline
  pre-commit / CI gate. The default exit-code behaviour is unchanged.

### Fixed

- `--only <paths>` matched nothing on Windows: the walker compared its absolute
  paths against the raw argument, so a relative path never matched and the scan
  silently covered no files. Both sides are now normalised (canonicalised), so
  pre-commit hooks that pass staged paths work across platforms.

## [0.1.3] - 2026-05-31

### Fixed

- MCP `classify` prompt now uses the `user` role instead of `system` — some MCP
  clients (e.g. Cursor) reject `system`-role prompt messages, so `/classify`
  silently failed. It works again.

### Added

- `scan --git` shows a progress spinner during the history walk, so a long scan
  on a large repository no longer looks like a hang.

## [0.1.2] - 2026-05-31

### Changed

- **Git-history scanning is now diff-only.** `scan --git` reports a secret at
  the commit that *added* it, scanning only added lines per commit instead of
  the full content of every file a commit touches — so a pre-existing secret is
  no longer re-reported every time a later commit modifies the same file.

### Added

- `leakferret mcp` prints a short hint when run interactively (it's a stdio
  JSON-RPC server meant to be launched by an editor/agent, not by hand).

## [0.1.1] - 2026-05-31

### Added — Rust rewrite

The first public release: a complete rewrite of the pre-alpha Ruby gem in
Rust, shipping as a single static binary plus thin language wrappers (Ruby,
Go, npm, GitHub Action, VS Code).

#### Supply chain

- Release tarballs are signed with **Sigstore/cosign** (keyless, via GitHub
  OIDC). Each `*.tar.gz` ships a matching `*.cosign.bundle`, verifiable with
  `cosign verify-blob` — see "Verifying the binaries" in the README.

#### Clarity

- When provider verification ran but was inconclusive (rate limit, network,
  no verifier for the key type), the finding now says so explicitly instead
  of the misleading "run with verifier" — which had already run.
- `rewrite --include-unknown` proposes fixes for UNKNOWN (unconfirmed)
  candidates, so offline rewrites are no longer gated on a live verifier or
  host-LLM classification.

#### Engine (`leakferret-core`)

- File walker on top of `ignore` (ripgrep's engine) — correct
  `.gitignore` semantics, parallel walk via `rayon`.
- 25+ built-in regex patterns ported from the Ruby gem (AWS, Stripe,
  GitHub PAT + fine-grained, GitLab PAT, Anthropic, OpenAI, Google,
  Slack, Twilio, SendGrid, Mailgun, GCP, Azure, PEM, JWT, Postgres,
  MySQL, MongoDB, Redis, generic assignment).
- **Fixture catalog** — versioned, Ed25519-signed JSON of known-public
  credentials (Stripe test keys, AWS canaries, RFC examples). O(1)
  HashSet exact lookup + regex set. 4 trust levels, 3 match strategies.
- **Provider verifiers** — 7 verifiers running concurrently with
  bounded parallelism. AWS uses native SigV4 (no `aws-sdk` dep).
- **Offline classifier** — 5-stage decision: catalog hit, verifier
  outcome, path hint, dummy marker, severity-by-path.
- **Host-LLM prompt** — `HostPrompt::for_findings` strips raw values
  and emits the structured candidate payload for the host model.
- **Rewriter** — 14 languages (Ruby, JS, TS, Python, YAML, JSON, Env,
  Shell, Go, Java, Kotlin, Scala, Rust, PHP). 5 secret-manager
  backends for seed commands.
- **Reporters** — pretty (owo-colors), JSON, SARIF 2.1.0.
- **Baseline + history** — `.leakferret-baseline.json` current-state
  + `.leakferret-history.jsonl` append-only audit log. HMAC-SHA256
  fingerprints with per-repo salt loaded from `.leakferret-salt`.
- **Engine orchestrator** wires scanner → fingerprint → verifier →
  classifier → rewriter → baseline → history.

#### CLI (`leakferret-cli`)

- `clap` v4 derive. Subcommands: `scan`, `verify`, `rewrite`,
  `baseline {init|show|ignore}`, `catalog {info|list|test}`, `mcp`.
- `verify --verify-mode {none|best-effort|only-verified|ever-verified}`.
- `rewrite --apply --backend {env|vault|doppler|aws-secrets-manager|infisical}`.
- Global `-q` / `-v` for tracing log level.

#### MCP server (`leakferret-mcp`)

- JSON-RPC 2.0 over stdio per `spec.modelcontextprotocol.io`.
- 5 tools: `scan_repository`, `classify_candidates`, `propose_rewrite`,
  `verify_finding`, `baseline_diff`.
- 1 prompt: `classify`.

#### Distribution

- CI: GitHub Actions for fmt / clippy / test (Linux + macOS + Windows)
  / release build, `cargo-deny` license + advisory check, MSRV check
  pinned to 1.78.
- Release workflow builds for 6 targets (linux-x64, linux-aarch64,
  darwin-x64, darwin-aarch64, windows-x64, windows-aarch64), tars,
  shasums, and uploads as draft GitHub Release.
- Dependabot weekly Cargo updates + monthly GH Actions updates.

#### Wrapper repos

| Repo | Distribution |
|---|---|
| `leakferret-ruby` | `gem install leakferret` — extconf.rb downloads binary |
| `leakferret-go`   | `go install github.com/leakferrethq/leakferret-go/cmd/leakferret@latest` |
| `leakferret-npm`  | `@leakferret/cli` + `@leakferret/mcp` — postinstall.js downloads binary |
| `leakferret-action` | composite GH Action, caches binary, uploads SARIF |
| `leakferret-catalog` | CC-BY-SA-4.0 JSON catalog, 20 initial entries |

### Archived

The pre-alpha Ruby gem (0.0.x) was the working spec for the Rust port and
has been removed from the tree — it's preserved in git history.

## [0.0.1] — pre-alpha Ruby gem

### Added
- Initial Ruby gem scaffold (`Scanner`, `Classifier`, `Rewriter`,
  `Reporter`, `Finding`, `Patterns`, `Gitignore`).
- MCP server in Ruby speaking JSON-RPC 2.0 over stdio.
- CLI subcommands: `scan`, `verify`, `rewrite`, `mcp`, `login`,
  `whoami`, `version`.
- Output formats: `pretty`, `json`, `sarif`.
- 21 regex patterns.
- Language-aware rewriter for 9 languages.
- Claude Code skill, VS Code extension scaffold, GitHub Action,
  pre-commit hook configs.
- RSpec test suite.
- Architecture docs + proxy-API spec.
