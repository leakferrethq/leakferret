<p align="center">
  <img src="brand/logo.png" alt="leakferret" width="440">
</p>

<p align="center">
  <a href="https://github.com/leakferrethq/leakferret/actions/workflows/ci.yml"><img src="https://github.com/leakferrethq/leakferret/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

**MCP-native secret scanner — verified findings, agent-applied rewrites.**

leakferret is one fast Rust binary that is engine, CLI, and MCP server in three
crates. It finds hardcoded secrets and API keys in your code, confirms which
ones are actually live by calling the provider, and rewrites the leak in place
to read from an environment variable instead. It runs from the terminal, in CI,
and as a tool your coding agent can call before it commits.

The full secret value never leaves your machine. Only a redacted
`AKIA...4XYZ` preview is ever written to a report, log, or network message.

---

## Quick start

Install however you like — every package ships the same prebuilt binary.

```bash
# Ruby gem
gem install leakferret

# npm (CLI)
npm i -g @leakferret/cli

# Go
go install github.com/leakferrethq/leakferret-go/cmd/leakferret@latest

# Native binary — download from GitHub Releases, unpack, and put it on $PATH:
#   https://github.com/leakferrethq/leakferret/releases

# Rust, from source
cargo install leakferret-cli
```

Then scan the current directory:

```bash
leakferret scan .
```

`scan` respects `.gitignore` and also reads dotfiles such as `.env`. Add
`--git` to walk commit history instead of the working tree.

> Every wrapper honors a `LEAKFERRET_BIN` environment variable pointing at a
> local binary, for offline or development use.

---

## How it works

leakferret runs findings through a five-station pipeline. Each station only
sees what it needs, and the raw secret never advances past disk.

1. **Scan** — a fast regex pre-filter over your files. Respects `.gitignore`,
   reads dotfiles like `.env`, and (with `--git`) walks history.
2. **Catalog** — every candidate is checked against a signed database of
   *known-public* example credentials: Stripe test keys,
   `AKIAIOSFODNN7EXAMPLE`, jwt.io samples, RFC examples. Matches are marked
   **FIXTURE** so documented examples never raise a false alarm. The catalog is
   bundled with the binary and can be refreshed and signature-verified.
3. **Classify** — each remaining candidate gets a verdict: **REAL**,
   **FIXTURE**, or **UNKNOWN**. This runs offline by default (path rules plus
   dummy-marker heuristics), or asks the host editor or agent's own language
   model — no extra API key, no added cost.
4. **Verify** — makes a single harmless API call to the provider to confirm a
   key is **LIVE**. Around 15 providers are covered natively (AWS SigV4,
   GitHub, GitLab, Stripe, OpenAI, Anthropic, Slack, Twilio, SendGrid,
   Mailgun, Datadog, Heroku, npm, PyPI, DigitalOcean), with a trufflehog binary
   fallback for the rest. The call goes straight from your machine to the
   provider — leakferret has no servers.
5. **Rewrite** — swaps a hardcoded literal for an environment-variable lookup
   (`ENV.fetch` / `os.environ` / `process.env`), appends a line to
   `.env.example`, and prints seed commands for your secret manager (env,
   Vault, Doppler, AWS Secrets Manager, or Infisical).

A **baseline** stores one-way HMAC fingerprints of known findings — never the
raw secret — so CI can fail only on *new* leaks.

---

## Use it with AI agents (MCP)

MCP (Model Context Protocol) is the open standard for giving coding agents
tools. Agents hardcode secrets too, and nobody reviews their diffs line by
line — leakferret lets the agent self-check before it commits.

Start the server over JSON-RPC on stdio:

```bash
npx @leakferret/mcp
```

Add it to your `mcpServers` config (Claude Desktop, Cursor, Continue,
Claude Code):

```json
{
  "mcpServers": {
    "leakferret": {
      "command": "npx",
      "args": ["@leakferret/mcp"]
    }
  }
}
```

If you installed the native binary, you can point at it directly instead:

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

Tools exposed: `scan_repository`, `classify_candidates`, `verify_finding`,
`propose_rewrite`, and `baseline_diff`. A `classify` prompt is also provided so
an agent can classify candidates inline using the model it already has.

---

## CLI reference

```text
leakferret scan      Regex pre-filter only (no classifier, no verifier)
leakferret verify    Scan + classify + provider verification
leakferret rewrite   Scan + classify + propose/apply ENV-fetch rewrites
leakferret baseline  Manage the per-repo fingerprint baseline
leakferret catalog   Load and inspect the fixture catalog
leakferret mcp       Start the MCP server on stdio
```

Common flags:

```bash
# scan
leakferret scan .                              # working tree
leakferret scan . --git                        # scan HEAD's commit history
leakferret scan . --git --all                  # scan every branch / tag
leakferret scan . --git --since HEAD~50        # bounded history window

# verify
leakferret verify .                            # best-effort verification
leakferret verify . --only-verified            # emit only confirmed-live keys
leakferret verify . --verify-mode ever-verified  # fail on historical leaks
leakferret verify . --verifier-timeout-secs 10

# rewrite
leakferret rewrite . --apply                   # write ENV.fetch in place
leakferret rewrite . --dry-run-diff            # show the diff, touch nothing
leakferret rewrite . --check                   # CI mode: exit 1 if rewrites pending
leakferret rewrite . --backend doppler         # seed cmds for your manager

# baseline  (scan/verify are read-only — they never write to your repo)
leakferret baseline init                       # create .leakferret-baseline.json (gitignores the salt)
leakferret verify . --update-baseline          # record current findings into the baseline
leakferret baseline show
leakferret baseline ignore --fingerprint <fp>  # acknowledge a finding

# catalog
leakferret catalog info
leakferret catalog test "sk_test_4eC39..."     # deterministic FIXTURE verdict
leakferret catalog refresh                      # fetch + signature-verify update
```

Shared flags on `scan` / `verify` / `rewrite`: `--format`, `--show-fixtures`,
`--exclude <glob>`, `--only <path>`, `--only-verified`.
`--backend` accepts `env`, `vault`, `doppler`, `aws-secrets-manager`,
`infisical`.

---

## Output formats

Choose with `--format`:

- **pretty** — colored terminal output (default).
- **json** — structured findings for scripting and pipelines.
- **sarif** — for GitHub Code Scanning. The GitHub Action wrapper
  (`leakferrethq/leakferret-action@v1`) uploads it for you.

---

## Privacy guarantee

This is the trust story, and a dedicated test enforces it:

> The full secret value lives only on disk. It is **never** written into any
> report, log, network message, or model prompt. Only a redacted first-4 +
> last-4 preview (for example `AKIA...4XYZ`) ever leaves the process.

Verification sends the key straight from your machine to the provider.
leakferret has no servers and collects nothing. Baselines store one-way HMAC
fingerprints, never the raw secret.

---

## How it compares

- **gitleaks** is a fast regex scanner. leakferret matches that pre-filter and
  adds provider verification, so you act on live keys instead of triaging
  regex noise.
- **trufflehog** verifies secrets against providers. leakferret matches that
  too — and adds the MCP/agent layer and the agent-applied rewrite that neither
  competitor has. The signed fixture catalog also keeps known-public example
  keys from being reported as live.

---

## Platforms

Prebuilt binaries for v0.1.0:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`
- `aarch64-pc-windows-msvc`

---

## Links

- Website: <https://leakferret.com>
- Source: <https://github.com/leakferrethq/leakferret>
- Catalog data: <https://github.com/leakferrethq/leakferret-catalog>
- Wrappers: [ruby](https://github.com/leakferrethq/leakferret-ruby) ·
  [go](https://github.com/leakferrethq/leakferret-go) ·
  [npm](https://github.com/leakferrethq/leakferret-npm) ·
  [action](https://github.com/leakferrethq/leakferret-action) ·
  [vscode](https://github.com/leakferrethq/leakferret-vscode)
- Maintainer: Maria Khan &lt;missusk@protonmail.com&gt;

## License

MIT for the engine, CLI, MCP server, and all language wrappers.
CC-BY-SA-4.0 for the fixture catalog data.

[trufflehog](https://github.com/trufflesecurity/trufflehog) is an optional,
user-installed AGPL-3.0 tool that leakferret invokes as a separate process for
fallback verification. It is not bundled, modified, or redistributed. See
[`NOTICE`](NOTICE).
