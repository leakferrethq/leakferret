# Security Policy

leakferret is a security tool: it finds, verifies, and rewrites hardcoded
secrets. We hold it to the standard it enforces. The full secret value never
leaves your machine — only a redacted `AKIA...4XYZ` preview is ever written to
a report, log, or network message — and we treat any deviation from that
invariant as a security bug.

## Supported versions

leakferret is pre-1.0; security fixes land on the latest `0.1.x` release.
Always run the most recent version.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue, pull
request, or discussion for anything exploitable.

Either channel is fine:

1. **GitHub Security Advisory (preferred).** Use *Security → Report a
   vulnerability* on this repository. It opens a private advisory that only the
   maintainers can see.
2. **Email.** <missusk@protonmail.com> with `[leakferret security]` in the
   subject. A PGP key is available on request if the report is sensitive.

Please include the affected version or commit, your platform, a minimal
reproduction, and the impact you observed.

> **Do not paste real secrets, live API keys, or customer data into a report.**
> Redact them the way leakferret would — first-4 and last-4 only
> (`ghp_AB...wXYZ`) — or share a synthetic key that still reproduces the issue.
> If a real credential is genuinely unavoidable, say so and we will arrange a
> secure channel first.

## What to expect

- **Acknowledgement within 72 hours.**
- An initial assessment — accepted, needs-info, or declined with reasoning —
  **within 7 days**.
- For accepted reports: a fix and a released patch as fast as the severity
  warrants (typically days for high-severity issues), followed by a GitHub
  Security Advisory that credits you unless you ask us not to.
- **Coordinated disclosure.** We ask for a reasonable window to ship a fix
  before any public write-up. We will not pursue legal action against
  good-faith research that respects this policy and the scope below.

## Scope

In scope:

- The engine, CLI, and MCP server (`leakferret-core`, `leakferret-cli`,
  `leakferret-mcp`).
- The language wrappers (Ruby, npm, Go, the GitHub Action, the VS Code
  extension) and their binary download and integrity-check logic.
- Any path where a raw secret could escape into output, logs, a report, the
  baseline or history files, a model prompt, or a network call. This is the
  invariant we care about most.
- The signed fixture catalog and its signature-verification path.

Out of scope:

- Vulnerabilities in the third-party providers leakferret verifies against, or
  in [`trufflehog`](https://github.com/trufflesecurity/trufflehog) — an
  optional, user-installed tool invoked as a separate process. Report those to
  their respective projects.
- Issues that require a modified or malicious build of leakferret itself.
- Output from automated scanners with no demonstrated, reproducible impact.

Thank you for helping keep leakferret and the people who rely on it safe.
