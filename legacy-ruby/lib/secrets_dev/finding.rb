# frozen_string_literal: true

require 'digest'

module SecretsDev
  # One candidate secret in a file. Carries enough context for the LLM
  # classifier to decide REAL vs FIXTURE without re-reading the file.
  #
  # The struct moves between four stages:
  #   1. Scanner    creates it with verdict :unknown
  #   2. Classifier sets verdict :real | :fixture | :unknown, fills reason
  #   3. Rewriter   fills replacement for the :real ones
  #   4. Reporter   renders it
  Finding = Struct.new(
    :path,        # String — relative path from scan root
    :line,        # Integer — 1-indexed
    :column,      # Integer — 1-indexed
    :match,       # String — the captured secret-looking value
    :pattern,     # Symbol  — Patterns entry name (e.g. :aws_access_key)
    :severity,    # Symbol  — :low | :medium | :high | :critical | :unknown
    :context,     # Array<String> — lines around the match (no trailing \n)
    :verdict,     # :real | :fixture | :unknown
    :reason,      # String — classifier explanation (nil before classify)
    :confidence,  # Float [0..1] — classifier confidence
    :replacement, # Hash — rewriter output: { :env_var, :patch, :env_example_line, :seed_command }
    keyword_init: true,
  ) do
    def real?
      verdict == :real
    end

    def fixture?
      verdict == :fixture
    end

    def unknown?
      verdict == :unknown || verdict.nil?
    end

    # Stable cache key used by the proxy/MCP layer to skip re-classification
    # of unchanged candidates across runs. SHA256 over the bits the LLM sees.
    def cache_key
      Digest::SHA256.hexdigest([pattern, redacted_match, context.join("\n")].join("\x00"))
    end

    # First 4 + last 4 chars. The full secret never crosses the wire.
    def redacted_match
      return match if match.to_s.length < 12

      "#{match[0, 4]}...#{match[-4, 4]}"
    end

    def to_h_safe
      {
        path: path,
        line: line,
        column: column,
        pattern: pattern,
        severity: severity,
        match_redacted: redacted_match,
        verdict: verdict,
        reason: reason,
        confidence: confidence,
      }
    end
  end
end
