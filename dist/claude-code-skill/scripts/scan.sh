#!/usr/bin/env bash
# Wrapper script the Claude Code skill calls to run a scan.
# Outputs JSON so the agent can parse and reason over the candidates.
set -euo pipefail

if ! command -v secrets-dev >/dev/null 2>&1; then
  echo '{"error": "secrets-dev gem not installed. Run: gem install secrets_dev"}' >&2
  exit 1
fi

PATH_ARG="${1:-.}"
shift || true

secrets-dev scan "$PATH_ARG" --format json "$@"
