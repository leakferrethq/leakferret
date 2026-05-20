---
name: leakferret
description: Find real hardcoded secrets in a codebase and propose env-var rewrites. Use when the user mentions secrets, leaked keys, hardcoded credentials, secret scanning, or asks "are there any keys in this repo".
---

# leakferret — context-aware secret scanner

You have access to a secret-scanning toolkit installed as the `leakferret`
gem. Use it any time the user asks about hardcoded credentials, leaked keys,
secret scanning, or wants help moving secrets out of source code.

## Workflow

1. **Scan** the relevant directory with the `leakferret scan` shell command.
   The output is JSON when you pass `--format json`; the CLI returns one
   finding per candidate with `path`, `line`, `pattern`, and a *redacted*
   match preview (first 4 + last 4 chars). The full secret value never
   appears in the JSON output.

2. **Classify** each candidate yourself by reading the surrounding context
   in the file. Mark each as one of:
   - **REAL** — a live secret that shipped in production source. Path is
     under `app/`, `lib/`, `src/`, `config/`, etc., AND the matched value
     has live provider structure.
   - **FIXTURE** — test fixture, mock, stub, example, doc. Path is under
     `spec/`, `test/`, `fixtures/`, `docs/`, etc., OR the value contains
     obvious dummy markers (`EXAMPLE`, `xxxx`, `placeholder`, `CHANGEME`).
   - **UNKNOWN** — can't tell from this context. Default here on ambiguity.

3. **For each REAL finding**, propose a rewrite. The toolkit's
   `propose_rewrite` command handles the language-aware mechanics — call it
   with the finding and it returns:
   - An `ENV.fetch` (or `process.env.X` / `os.environ['X']` etc.) call to
     replace the literal
   - A `.env.example` line the user should add
   - Seed commands for Vault / Doppler / AWS Secrets Manager — the user
     runs these themselves; the tool never sees or stores the secret value

4. **Confirm with the user before applying** any rewrite. Show the diff
   first.

## CLI reference

```
leakferret scan PATH [--format json|pretty|sarif] [--exclude GLOB]
leakferret verify PATH                  # adds heuristic verdicts
leakferret rewrite PATH [--apply]       # propose rewrites; --apply writes them
leakferret mcp                          # used by IDE integrations; ignore here
```

## Reasoning prompt (use this verbatim when classifying)

```
You're reviewing regex hits that may be hardcoded secrets in source code.
For each candidate you'll get: file path, pattern name, redacted preview
(first 4 + last 4 chars only), ~7 lines of surrounding context.

Classify each as REAL, FIXTURE, or UNKNOWN. Bias toward FIXTURE on paths
containing spec/ test/ tests/ fixtures/ examples/ docs/ demo/ sample/
mock/ dummy/ or files named .env.example / .env.sample. Bias toward REAL
on paths under app/ lib/ src/ config/ (except config/credentials.yml.enc)
with live provider structure. Default to UNKNOWN on genuine ambiguity.

Output JSON only: [{"id": "...", "verdict": "REAL|FIXTURE|UNKNOWN",
"reason": "...", "confidence": 0.0-1.0}]
```

## Privacy

This skill never transmits secret values over the network. The CLI redacts
matches to the first 4 + last 4 chars before any output. Seed commands
emit placeholder text the user fills in locally.

## Installation

```bash
gem install leakferret
# Then add to .mcp.json if you also want the MCP server form:
#   { "mcpServers": { "leakferret": { "command": "leakferret", "args": ["mcp"] } } }
```
