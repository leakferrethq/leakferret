# leakferret for VS Code

Inline secret detection that uses **your own** Copilot / Claude model for
classification, so the extension is free to install and incurs no separate
LLM bill.

## What it does

- On file save (or via command), scans the current file with `leakferret`
  (Ruby gem, regex pre-filter).
- For each candidate, calls `vscode.lm.sendRequest()` against whichever
  language model is configured (GitHub Copilot Chat by default; Claude /
  OpenAI if the user has those providers wired up).
- Surfaces:
  - REAL findings as Error diagnostics (red underline)
  - UNKNOWN as Warning (yellow)
  - FIXTURE not shown
- Quick Fix on each diagnostic: replace the literal with the right
  language-aware env-var lookup (`ENV.fetch` / `process.env.X` / etc.) and
  add a line to `.env.example`.

## Install

1. `gem install leakferret` (the engine the extension shells out to)
2. Install this extension from the VS Code Marketplace.

That's it. No accounts, no API keys, no SaaS dependency.

## Privacy

The extension never sends the actual secret value anywhere. The CLI
redacts each match to first 4 + last 4 chars before any output. The
classification call to your LM provider receives only the redacted preview
and a few lines of surrounding context — never the secret itself.

## Settings

- `leakferret.gemPath` — path to the `leakferret` CLI (default: PATH lookup).
- `leakferret.classifyOnSave` — run the classifier on every save (default: true).
- `leakferret.modelFamily` — preferred LM family (default: `gpt-4o`).
