# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module SecretsDev
  # Classifier has three operating modes:
  #
  #   :offline   pure heuristics, no LLM. Path hints + pattern severity +
  #              context regexes mark each Finding REAL / FIXTURE / UNKNOWN.
  #              Free, fast, lower precision.
  #
  #   :host_llm  delegates to whichever LLM the host environment provides.
  #              In an MCP server context, the Classifier #serialize_for_host
  #              method produces the structured payload the host model will
  #              reason over via the agent's own conversation. In a VS Code
  #              extension context, the extension calls vscode.lm with the
  #              same payload. The Ruby side never makes the LLM HTTP call.
  #
  #   :api       optional paid-tier mode: POST batches to our own classify
  #              endpoint, which proxies to Claude Haiku. Used for headless
  #              flows (GitHub Action, pre-commit) where no host LLM exists.
  class Classifier
    SYSTEM_PROMPT = <<~PROMPT.strip
      You're reviewing regex hits that may be hardcoded secrets in source code.
      For each candidate you'll get: the file path, the pattern name, a redacted
      preview of the matched value (first 4 and last 4 chars only), and ~7 lines
      of surrounding context.

      Classify each candidate as one of:
        REAL    - looks like a live secret that shipped in production source
        FIXTURE - looks like a test fixture, mock, stub, example, doc, or
                  obvious dummy value (sk_test_xxx, AKIAIOSFODNN7EXAMPLE,
                  redacted/placeholder strings, etc.)
        UNKNOWN - can't tell from this context alone

      Bias toward FIXTURE when the path contains spec/, test/, tests/,
      fixtures/, examples/, docs/, demo/, sample/, mock/, dummy/, or
      filenames like .env.example / .env.sample.

      Bias toward REAL when the path is under app/, lib/, src/, config/
      (excluding config/credentials.yml.enc which is already encrypted),
      cmd/, or services/, AND the matched value has live provider structure.

      Default to UNKNOWN when there's genuine ambiguity. Don't guess.

      Output strict JSON only, no prose:
      [{"id": "...", "verdict": "REAL|FIXTURE|UNKNOWN", "reason": "...", "confidence": 0.0-1.0}, ...]
    PROMPT

    def initialize(mode: :offline, api_endpoint: ENV['SECRETS_DEV_API'], api_token: nil)
      @mode = mode
      @api_endpoint = api_endpoint || 'https://api.secrets-dev.com/v1/classify'
      @api_token = api_token || load_token
    end

    def classify(findings)
      return findings if findings.empty?

      case @mode
      when :offline  then classify_offline(findings)
      when :api      then classify_via_api(findings)
      when :host_llm then raise ArgumentError, 'host_llm mode is consumed via serialize_for_host'
      else
        raise ArgumentError, "unknown mode: #{@mode.inspect}"
      end
      findings
    end

    def serialize_for_host(findings)
      {
        system: SYSTEM_PROMPT,
        candidates: findings.map.with_index do |f, idx|
          {
            id: idx.to_s,
            path: f.path,
            pattern: f.pattern.to_s,
            severity: f.severity.to_s,
            match_redacted: f.redacted_match,
            context: f.context,
          }
        end,
      }
    end

    def apply_verdicts!(findings, verdict_response)
      response = verdict_response.is_a?(String) ? JSON.parse(verdict_response) : verdict_response
      response.each do |v|
        idx = v['id'].to_i
        f = findings[idx]
        next unless f

        verdict = v['verdict'].to_s.downcase.to_sym
        f.verdict = %i[real fixture unknown].include?(verdict) ? verdict : :unknown
        f.reason = v['reason']
        f.confidence = v['confidence']&.to_f
      end
      findings
    end

    private

    def classify_offline(findings)
      findings.each do |f|
        if Patterns.likely_fixture_path?(f.path)
          f.verdict = :fixture
          f.reason = "Path matches fixture/test/example heuristic (#{f.path})."
          f.confidence = 0.7
        elsif obvious_dummy?(f.match)
          f.verdict = :fixture
          f.reason = 'Matched value is a documented dummy (EXAMPLE / xxxx / test).'
          f.confidence = 0.9
        elsif %i[critical high].include?(f.severity) && app_path?(f.path)
          f.verdict = :real
          f.reason = "High-severity pattern in application path (#{f.path})."
          f.confidence = 0.65
        else
          f.verdict = :unknown
          f.reason = 'Offline heuristics inconclusive; run with a host LLM for higher precision.'
          f.confidence = 0.3
        end
      end
    end

    DUMMY_MARKERS = %w[EXAMPLE example xxxx XXXX test_xxx placeholder REDACTED CHANGEME].freeze

    def obvious_dummy?(value)
      DUMMY_MARKERS.any? { |m| value.include?(m) }
    end

    APP_PATH_PREFIXES = %w[app/ lib/ src/ config/ cmd/ services/ pkg/ internal/].freeze

    def app_path?(path)
      APP_PATH_PREFIXES.any? { |p| path.start_with?(p) }
    end

    def classify_via_api(findings)
      return classify_offline(findings) unless @api_token

      uri = URI.parse(@api_endpoint)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.read_timeout = 30

      findings.each_slice(50) do |batch|
        process_api_batch(http, uri, batch)
      end
    rescue StandardError => e
      warn "[secrets-dev] Classifier API error: #{e.message}. Falling back to offline."
      classify_offline(findings)
    end

    def process_api_batch(http, uri, batch)
      req = Net::HTTP::Post.new(uri.request_uri)
      req['Authorization'] = "Bearer #{@api_token}"
      req['Content-Type']  = 'application/json'
      req['User-Agent']    = "secrets-dev/#{SecretsDev::VERSION}"
      req.body = JSON.generate(
        candidates: batch.map.with_index do |f, idx|
          {
            id: idx.to_s,
            path: f.path,
            pattern: f.pattern.to_s,
            match_redacted: f.redacted_match,
            context: f.context,
          }
        end,
        client: { version: SecretsDev::VERSION, surface: 'cli' },
      )

      response = request_with_retry(http, req)

      case response.code.to_i
      when 200
        apply_verdicts!(batch, JSON.parse(response.body).fetch('verdicts'))
      when 402
        warn '[secrets-dev] Free quota exhausted. Falling back to offline.'
        classify_offline(batch)
      else
        warn "[secrets-dev] Classifier API returned #{response.code}. Falling back to offline."
        classify_offline(batch)
      end
    end

    def request_with_retry(http, req, max_attempts: 3)
      attempts = 0
      response = nil
      loop do
        attempts += 1
        response = http.request(req)
        break unless response.code == '429' && attempts < max_attempts

        retry_after = (response['Retry-After'] || 5).to_i
        warn "[secrets-dev] Rate limited. Sleeping #{retry_after}s..."
        sleep retry_after
      end
      response
    end

    def load_token
      path = File.expand_path('~/.secrets-dev/config')
      return nil unless File.file?(path)

      config = JSON.parse(File.read(path))
      config['token']
    rescue StandardError
      nil
    end
  end
end
