# Architecture

`leakferret` is a four-stage pipeline that flows the same `Finding`
struct through every distribution surface.

```
                          ┌──────────────┐
                          │   Scanner    │  regex pre-filter, file walk
                          │ (lib/.../    │  respects .gitignore, skips
                          │  scanner.rb) │  binaries, captures context
                          └──────┬───────┘
                                 │ Finding[]  (verdict: :unknown)
                                 ▼
                          ┌──────────────┐
              offline ────│              │──── host_llm  (Claude Code,
              heuristic   │  Classifier  │     VS Code lm.sendRequest,
              (no LLM)    │              │     MCP host model)
                          │              │
                          │              │──── api  (proxy to hosted
                          │              │     classifier, paid tier)
                          └──────┬───────┘
                                 │ Finding[]  (verdict: :real|:fixture|:unknown)
                                 ▼
                          ┌──────────────┐
                          │   Rewriter   │  language-aware ENV.fetch /
                          │              │  process.env / os.environ
                          │              │  rewrite for :real findings
                          └──────┬───────┘
                                 │ Finding[]  (replacement filled in)
                                 ▼
                          ┌──────────────┐
                          │   Reporter   │  pretty | json | sarif
                          └──────────────┘
```

## Distribution surfaces, all driven by the same engine

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   gem (CLI)                  Claude Code skill              │
│   ─────────────              ─────────────────              │
│   bin/leakferret            dist/claude-code-skill/        │
│       scan                       SKILL.md                   │
│       verify                     scripts/scan.sh            │
│       rewrite                    scripts/rewrite.sh         │
│       mcp                                                   │
│                                                             │
│   MCP server                 VS Code extension              │
│   ──────────                 ──────────────────             │
│   lib/.../mcp_server.rb      dist/vscode-extension/         │
│   tools:                         src/extension.ts           │
│     scan_repository              uses vscode.lm.sendRequest │
│     classify_candidates          for classification         │
│     propose_rewrite                                         │
│                                                             │
│   GitHub Action              pre-commit hook                │
│   ─────────────              ───────────────                │
│   dist/github-action/        dist/pre-commit/               │
│       action.yml                 .pre-commit-hooks.yaml     │
│   uploads SARIF              passes staged files via --only │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌──────────────────────────────┐
              │   lib/leakferret/*.rb       │
              │   (the engine — one source   │
              │    of truth for all six)     │
              └──────────────────────────────┘
```

## Why MCP-first

The Anthropic /  Microsoft / Cursor / Continue ecosystems all converged
on MCP as the protocol for tools that an AI agent calls. By implementing
the server in `lib/leakferret/mcp_server.rb`, we hit every host that
speaks MCP from one Ruby file. The host's own LLM does the classification
reasoning — we don't own an Anthropic key, the user's existing subscription
covers it.

For surfaces that don't have a host LLM (CLI, pre-commit, GitHub Action),
the same `Classifier` falls back to either offline heuristics or an
optional hosted-API proxy. The user picks.

## Why redact aggressively at the scanner

Every output path — pretty terminal, JSON, SARIF, MCP tool response,
classifier prompt — uses `Finding#redacted_match`, which is hard-capped
at 8 visible chars from the original secret. This is the privacy
contract that lets us pitch the tool to security-conscious orgs without
asking them to trust us. The full secret value lives only in the file on
disk; it never enters any output buffer.

## The Finding struct (the contract)

```ruby
Finding = Struct.new(
  :path, :line, :column, :match, :pattern, :severity,
  :context, :verdict, :reason, :confidence, :replacement,
  keyword_init: true,
)
```

Every stage reads/writes specific fields. Scanner writes `path` through
`context`. Classifier writes `verdict`, `reason`, `confidence`. Rewriter
writes `replacement`. Reporter reads everything.

This is why each distribution surface can be tiny — they just need to
move `Finding`s through stages, not reimplement the logic.

## Performance

For repos up to ~100k files, pure-Ruby walk + per-line `Regexp.scan` is
fast enough. For larger monorepos, the v1 plan is to swap the inner loop
for `ripgrep --json` when `rg` is on $PATH — same `Finding` output,
~50–100x faster.

The LM classification is the latency floor everywhere except `scan`
(which doesn't call the LM at all). On a typical PR diff with 5–20
candidates and Claude Haiku 4.5, classification finishes in 1–3 seconds.
