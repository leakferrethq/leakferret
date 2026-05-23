# frozen_string_literal: true

require 'json'
require 'pastel'

module SecretsDev
  # Formats Findings for stdout. `pretty` is the dev-facing form; `json` and
  # `sarif` are for CI / programmatic consumers.
  #
  # SARIF (Static Analysis Results Interchange Format) is what GitHub Code
  # Scanning, Azure DevOps, and most enterprise tools ingest natively. Worth
  # supporting from v0 because it removes the integration friction that
  # otherwise kills adoption in larger orgs.
  class Reporter
    def initialize(format: 'pretty', stream: $stdout, show_fixtures: false)
      @format = format
      @stream = stream
      @show_fixtures = show_fixtures
      @pastel = Pastel.new(enabled: stream.tty?)
    end

    def emit(findings)
      findings = findings.reject(&:fixture?) unless @show_fixtures

      case @format
      when 'json'  then emit_json(findings)
      when 'sarif' then emit_sarif(findings)
      else              emit_pretty(findings)
      end
    end

    # Exit code helper. 0 if no REAL findings; 1 otherwise.
    def self.exit_code(findings)
      findings.any?(&:real?) ? 1 : 0
    end

    private

    def emit_pretty(findings)
      if findings.empty?
        @stream.puts @pastel.green.bold('  ✔ no candidate secrets found')
        return
      end

      grouped = findings.group_by(&:path)
      grouped.each do |path, group|
        @stream.puts @pastel.bold.cyan(path)
        group.each do |f|
          verdict_tag =
            case f.verdict
            when :real    then @pastel.red.bold('REAL')
            when :fixture then @pastel.dim('FIXTURE')
            else               @pastel.yellow('UNKNOWN')
            end
          sev_tag = severity_tag(f.severity)

          conf = f.confidence ? @pastel.dim(" (#{(f.confidence * 100).round}%)") : ''
          @stream.puts "  #{@pastel.dim("L#{f.line}:#{f.column}")}  " \
                       "#{verdict_tag}#{conf}  #{sev_tag}  " \
                       "#{@pastel.magenta(f.pattern.to_s)}  #{@pastel.dim(f.redacted_match)}"

          @stream.puts "    #{@pastel.dim('↳')} #{@pastel.dim(f.reason)}" if f.reason

          if f.replacement
            @stream.puts "    #{@pastel.dim('-')} #{@pastel.red(f.replacement.old_line)}"
            @stream.puts "    #{@pastel.dim('+')} #{@pastel.green(f.replacement.new_line)}"
          end
        end
        @stream.puts
      end

      total = findings.size
      real_count = findings.count(&:real?)
      unknown_count = findings.count(&:unknown?)

      @stream.puts @pastel.bold("#{total} finding(s)  ·  ") +
                   @pastel.red.bold("#{real_count} real") +
                   @pastel.bold('  ·  ') +
                   @pastel.yellow("#{unknown_count} unknown")
    end

    def severity_tag(severity)
      case severity
      when :critical then @pastel.on_red.white.bold(' CRITICAL ')
      when :high     then @pastel.red(' HIGH ')
      when :medium   then @pastel.yellow(' MED ')
      when :low      then @pastel.dim(' LOW ')
      else                @pastel.dim(' ? ')
      end
    end

    def emit_json(findings)
      @stream.puts JSON.pretty_generate(findings.map(&:to_h_safe))
    end

    def emit_sarif(findings)
      sarif = {
        version: '2.1.0',
        '$schema': 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json',
        runs: [{
          tool: {
            driver: {
              name: 'secrets-dev',
              version: SecretsDev::VERSION,
              informationUri: 'https://github.com/leakferrethq/secrets-dev',
              rules: Patterns.all.map do |p|
                {
                  id: p[:name].to_s,
                  name: p[:name].to_s,
                  shortDescription: { text: p[:description] },
                  defaultConfiguration: { level: sarif_level(p[:severity]) },
                }
              end,
            },
          },
          results: findings.map do |f|
            {
              ruleId: f.pattern.to_s,
              level: sarif_level(f.severity, f.verdict),
              message: { text: "#{f.pattern}: #{f.redacted_match} (#{f.verdict})" },
              locations: [{
                physicalLocation: {
                  artifactLocation: { uri: f.path },
                  region: { startLine: f.line, startColumn: f.column },
                },
              }],
              properties: { verdict: f.verdict.to_s, confidence: f.confidence },
            }
          end,
        }],
      }
      @stream.puts JSON.pretty_generate(sarif)
    end

    def sarif_level(severity, verdict = nil)
      return 'note' if verdict == :fixture
      return 'warning' if verdict == :unknown

      case severity
      when :critical, :high then 'error'
      when :medium          then 'warning'
      else                       'note'
      end
    end
  end
end
