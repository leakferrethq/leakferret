# Proxy API spec (paid-tier classifier)

This document describes the hosted classifier API used by headless
surfaces (GitHub Action, pre-commit hook) that don't have a host LLM
available. The MCP / Claude Code / VS Code surfaces do **not** use this
API — they use the host's own LLM via the existing user subscription.

## Auth

Bearer token in the `Authorization` header. Anonymous tokens are
auto-issued via `leakferret login`; account-bound tokens come from the
hosted dashboard.

```
Authorization: Bearer sdv_anon_<32-hex>
```

## POST /v1/classify

```json
{
  "candidates": [
    {
      "id": "0",
      "path": "app/services/aws_client.rb",
      "pattern": "aws_access_key",
      "match_redacted": "AKIA...MPLE",
      "context": [
        "class AwsClient",
        "  ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        "end"
      ]
    }
  ],
  "client": { "version": "0.0.1", "surface": "cli" }
}
```

### Response 200

```json
{
  "verdicts": [
    {
      "id": "0",
      "verdict": "real",
      "reason": "Top-level constant assignment in app/services/ with live AWS Access Key ID structure.",
      "confidence": 0.94,
      "verdict_cache_key": "sha256:..."
    }
  ],
  "quota": { "used": 47, "limit": 1000, "resets_at": "2026-06-26T00:00:00Z" }
}
```

### Response headers (always present)

```
X-Quota-Used: 47
X-Quota-Limit: 1000
X-Quota-Resets-At: 2026-06-26T00:00:00Z
X-Ratelimit-Remaining: 58
X-Ratelimit-Reset: 12
```

### Hard rules (server-enforced)

- `match_redacted` ≤ 8 chars from original (first 4 + last 4). 422 otherwise.
- `context` ≤ 8 lines and ≤ 8 KB total. 422 otherwise.
- ≤ 50 candidates per request. Client batches.
- Server logs metadata only (timestamps, counts, verdict distribution).
  Never `context` bodies, `match_redacted` values, or paths.

### Errors

| Code | Reason                | Notes                                  |
|------|-----------------------|----------------------------------------|
| 401  | invalid_token         | Bad / expired / revoked.               |
| 402  | quota_exhausted       | Body has upgrade_url.                  |
| 422  | invalid_request       | Oversized context, un-redacted match.  |
| 429  | rate_limited          | Retry-After header set.                |
| 503  | upstream_unavailable  | Model provider issue. Backoff + retry. |

## GET /v1/quota

```json
{ "used": 47, "limit": 1000, "resets_at": "...", "kind": "anonymous" }
```

## GET /v1/health

```json
{ "ok": true, "model": "claude-haiku-4-5-20251001", "version": "..." }
```

## Caching contract

`verdict_cache_key = sha256(pattern + match_redacted + context.join('\n'))`.
Client stores `{ verdict_cache_key → verdict }` in `~/.leakferret/cache.json`
and skips re-classification of identical findings.

Effects:
- Second scan with no code changes: zero LLM calls.
- Pre-commit hook on incremental diffs: cents/month.

## Model routing (server-side, not in public API)

- Default: Claude Haiku 4.5.
- Fallback: smaller model via internal gateway when Haiku rate-limited.
- Enterprise: per-org override to customer-owned endpoint (Bedrock,
  Azure OpenAI, on-prem). Same response shape.
