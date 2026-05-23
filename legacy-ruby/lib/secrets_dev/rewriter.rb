# frozen_string_literal: true

module SecretsDev
  # Proposes a code-edit that swaps a hardcoded secret for an env-var lookup
  # in whichever language the file is written in, plus a `.env.example`
  # entry and an optional secret-manager seeding command for the developer
  # to run themselves.
  #
  # We never store the secret value. The seeding command is emitted with
  # placeholder text the user fills in locally.
  #
  # v0 is regex-based, language-aware by file extension. Reliable for the
  # common case (assignment to a variable / constant / hash value with the
  # secret in quotes). The v1 path is AST rewriting via Prism (Ruby),
  # tree-sitter (everything else); same Rewriter#propose interface.
  class Rewriter
    SUPPORTED_LANGUAGES = %i[ruby javascript typescript python yaml json env shell go java].freeze

    Replacement = Struct.new(
      :env_var,           # 'AWS_ACCESS_KEY'
      :old_line,          # original line text (full line, no \n)
      :new_line,          # replacement line text (full line, no \n)
      :env_example_line,  # 'AWS_ACCESS_KEY='
      :seed_commands,     # Array<String> — commands the user runs (vault / doppler / aws sm)
      keyword_init: true,
    )

    def initialize(secret_backend: :env)
      @secret_backend = secret_backend # :env | :vault | :doppler | :aws_sm
    end

    # @param finding [Finding]
    # @return [Replacement, nil] nil if we can't safely rewrite
    def propose(finding)
      return nil unless finding.real?

      lang = detect_language(finding.path)
      return nil unless SUPPORTED_LANGUAGES.include?(lang)

      env_var = derive_env_var_name(finding)
      old_line = finding.context[middle_index(finding.context)] || ''
      new_line = rewrite_line(old_line, finding.match, env_var, lang)
      return nil if new_line.nil? || new_line == old_line

      Replacement.new(
        env_var: env_var,
        old_line: old_line,
        new_line: new_line,
        env_example_line: "#{env_var}=",
        seed_commands: seed_commands(env_var),
      )
    end

    private

    def detect_language(path)
      case File.extname(path).downcase
      when '.rb', '.erb', '.rake' then :ruby
      when '.js', '.mjs', '.cjs', '.jsx', '.vue', '.svelte' then :javascript
      when '.ts', '.tsx' then :typescript
      when '.py' then :python
      when '.yml', '.yaml' then :yaml
      when '.json', '.json5' then :json
      when '.sh', '.bash', '.zsh', '.fish' then :shell
      when '.go' then :go
      when '.java', '.kt', '.scala' then :java
      else
        :env if File.basename(path).start_with?('.env')
      end
    end

    # Best guess based on the assignment LHS in the line, with the pattern
    # name as a last-resort fallback.
    def derive_env_var_name(finding)
      line = finding.context[middle_index(finding.context)].to_s

      lhs =
        line[/\b([A-Z][A-Z0-9_]+)\s*[:=]/, 1] ||                  # SHOUTY constant
          line[/\b([a-z_][a-z0-9_]*)\s*[:=]/, 1]&.upcase ||       # snake_case var
          line[/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*:/, 1]&.gsub(/(?<=[a-z])([A-Z])/, '_\1')&.upcase # camelCase hash key

      lhs ||= finding.pattern.to_s.upcase.gsub('-', '_')
      lhs.gsub(/[^A-Z0-9_]/, '_').sub(/^_+/, '').sub(/_+$/, '')
    end

    def middle_index(context)
      context.length / 2
    end

    def rewrite_line(line, secret_value, env_var, lang)
      # Defensive: the secret must actually appear in the line we're rewriting.
      return nil unless line.include?(secret_value)

      replacement = env_var_call_for(lang, env_var)
      return nil unless replacement

      # Replace the quoted string containing the secret (and the surrounding
      # quotes) with the env-var call. Be tolerant of single/double quotes
      # and escape-sequences.
      quote_pattern = /(['"])#{Regexp.escape(secret_value)}\1/
      if line.match?(quote_pattern)
        line.sub(quote_pattern, replacement)
      else
        # Fall back: just replace the value, leave quotes alone. Caller will
        # see the diff and decide.
        line.sub(secret_value, replacement)
      end
    end

    def env_var_call_for(lang, name)
      case lang
      when :ruby       then "ENV.fetch('#{name}')"
      when :javascript, :typescript then "process.env.#{name}"
      when :python     then "os.environ['#{name}']"
      when :yaml       then "${#{name}}"           # plus a comment for the user to wire up env interpolation
      when :json       then nil                    # JSON doesn't support env refs natively; skip
      when :env        then nil                    # already env; nothing to rewrite
      when :shell      then "${#{name}}"
      when :go         then "os.Getenv(\"#{name}\")"
      when :java       then "System.getenv(\"#{name}\")"
      end
    end

    def seed_commands(env_var)
      placeholder = "<paste-#{env_var.downcase}-value-here>"
      [
        "# Pick one — secrets-dev never stores or transmits the actual value:",
        "export #{env_var}=#{placeholder}",
        "doppler secrets set #{env_var}=#{placeholder}",
        "vault kv put secret/app #{env_var}=#{placeholder}",
        "aws secretsmanager put-secret-value --secret-id #{env_var.downcase.tr('_', '-')} --secret-string \"#{placeholder}\"",
      ]
    end
  end
end
