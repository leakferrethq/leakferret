# frozen_string_literal: true

module SecretsDev
  # Regex patterns for the cheap pre-filter pass.
  #
  # Two design rules every pattern follows:
  #   1. The :regex captures the secret value (group 1) when the surrounding
  #      assignment chrome is irrelevant. Otherwise the whole match IS the value.
  #   2. The :description is short enough to fit in a status-bar tooltip.
  #
  # Provider-specific patterns are tight enough that the false-positive rate is
  # moderate without the LLM step. The generic `:secret_assignment` pattern is
  # deliberately loose — that's the layer the host model earns its keep on.
  module Patterns
    DEFINITIONS = [
      # ----- AWS -----
      {
        name: :aws_access_key,
        regex: /\b((?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|APKA)[A-Z0-9]{16})\b/,
        description: 'AWS Access Key ID',
        severity: :high,
      },
      {
        name: :aws_secret_key,
        regex: /aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9\/+=]{40})['"]?/i,
        description: 'AWS Secret Access Key',
        severity: :critical,
      },
      {
        name: :aws_session_token,
        regex: /aws[_-]?session[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9\/+=]{100,})['"]?/i,
        description: 'AWS Session Token',
        severity: :high,
      },

      # ----- Stripe -----
      {
        name: :stripe_secret,
        regex: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b/,
        description: 'Stripe Secret Key',
        severity: :critical,
      },
      {
        name: :stripe_publishable,
        regex: /\b(pk_(?:live|test)_[0-9a-zA-Z]{24,})\b/,
        description: 'Stripe Publishable Key (low-sev — publishable by design)',
        severity: :low,
      },

      # ----- GitHub -----
      {
        name: :github_token,
        regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/,
        description: 'GitHub Personal Access / OAuth / App / Refresh / User Token',
        severity: :critical,
      },
      {
        name: :github_fine_grained,
        regex: /\b(github_pat_[A-Za-z0-9_]{82})\b/,
        description: 'GitHub Fine-Grained PAT',
        severity: :critical,
      },

      # ----- LLM provider keys -----
      {
        name: :anthropic_key,
        regex: /\b(sk-ant-[A-Za-z0-9_-]{40,})\b/,
        description: 'Anthropic API Key',
        severity: :critical,
      },
      {
        name: :openai_key,
        # `sk-` followed by either the legacy 48-char form, the `proj-` form,
        # or the new `svcacct-` form.
        regex: /\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,})\b/,
        description: 'OpenAI API Key',
        severity: :critical,
      },
      {
        name: :google_api_key,
        regex: /\b(AIza[0-9A-Za-z_-]{35})\b/,
        description: 'Google / Firebase API Key',
        severity: :high,
      },

      # ----- Communications / SaaS -----
      {
        name: :slack_token,
        regex: /\b(xox[abprs]-(?:\d+-)*[A-Za-z0-9-]{10,48})\b/,
        description: 'Slack Token',
        severity: :high,
      },
      {
        name: :slack_webhook,
        regex: %r{\b(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)\b},
        description: 'Slack Incoming Webhook URL',
        severity: :medium,
      },
      {
        name: :twilio_key,
        regex: /\b(SK[a-f0-9]{32})\b/,
        description: 'Twilio API Key SID',
        severity: :high,
      },
      {
        name: :sendgrid_key,
        regex: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/,
        description: 'SendGrid API Key',
        severity: :high,
      },
      {
        name: :mailgun_key,
        regex: /\b(key-[a-f0-9]{32})\b/,
        description: 'Mailgun API Key',
        severity: :medium,
      },

      # ----- Cloud platforms -----
      {
        name: :gcp_service_account,
        regex: /"type"\s*:\s*"service_account"[^}]*"private_key_id"\s*:\s*"([a-f0-9]{40})"/m,
        description: 'GCP Service Account JSON (private_key_id)',
        severity: :critical,
      },
      {
        name: :azure_storage,
        regex: /DefaultEndpointsProtocol=https;AccountName=([A-Za-z0-9]+);AccountKey=([A-Za-z0-9+\/=]{88});/,
        description: 'Azure Storage Account Connection String',
        severity: :critical,
      },

      # ----- Crypto material -----
      {
        name: :pem_private_key,
        regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
        description: 'PEM-encoded Private Key',
        severity: :critical,
      },
      {
        name: :jwt,
        regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
        description: 'JWT (header.payload.signature)',
        severity: :medium,
      },

      # ----- Database URLs -----
      {
        name: :postgres_url,
        regex: %r{\b(postgres(?:ql)?://[^:\s'"]+:[^@\s'"]+@[^\s'"]+)\b},
        description: 'PostgreSQL URL with credentials',
        severity: :high,
      },
      {
        name: :mysql_url,
        regex: %r{\b(mysql://[^:\s'"]+:[^@\s'"]+@[^\s'"]+)\b},
        description: 'MySQL URL with credentials',
        severity: :high,
      },
      {
        name: :mongodb_url,
        regex: %r{\b(mongodb(?:\+srv)?://[^:\s'"]+:[^@\s'"]+@[^\s'"]+)\b},
        description: 'MongoDB URL with credentials',
        severity: :high,
      },
      {
        name: :redis_url_auth,
        regex: %r{\b(redis(?:s)?://[^:\s'"]*:[^@\s'"]+@[^\s'"]+)\b},
        description: 'Redis URL with credentials',
        severity: :high,
      },

      # ----- Generic (the noisy one) -----
      {
        name: :secret_assignment,
        # Catch the assignment form. Last line of defense.
        regex: /(?:password|passwd|secret|token|api[_-]?key|apikey|auth[_-]?token)\s*[:=]\s*['"]([^'"\s]{12,})['"]/i,
        description: 'Generic secret-shaped assignment',
        severity: :unknown,
      },
    ].freeze

    def self.all
      DEFINITIONS
    end

    def self.find_by(name)
      DEFINITIONS.find { |p| p[:name] == name }
    end

    # Path heuristics — used by the classifier prompt and by `secrets-dev verify
    # --offline` (regex-only mode) to bias toward FIXTURE on test-shaped paths.
    FIXTURE_PATH_HINTS = %w[
      spec/ test/ tests/ __tests__/ fixtures/ examples/ docs/ doc/
      example/ examples/ sample/ samples/ demo/ tutorial/
      .env.example .env.sample .env.template
      mock/ mocks/ stub/ stubs/ dummy/
    ].freeze

    def self.likely_fixture_path?(path)
      FIXTURE_PATH_HINTS.any? { |hint| path.include?(hint) }
    end
  end
end
