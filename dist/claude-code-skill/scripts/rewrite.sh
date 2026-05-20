#!/usr/bin/env bash
# Wrapper the skill calls to propose rewrites. Always dry-run; the agent
# shows the user the diff and gets confirmation before applying.
set -euo pipefail

PATH_ARG="${1:-.}"
shift || true

secrets-dev rewrite "$PATH_ARG" --format json "$@"
