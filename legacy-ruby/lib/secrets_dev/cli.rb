# frozen_string_literal: true

require 'thor'
require 'pastel'
require 'json'
require 'fileutils'

module SecretsDev
  # Thor-based CLI.
  #
  #   secrets-dev scan PATH               regex pre-filter, no LLM
  #   secrets-dev verify PATH             scan + offline heuristic classify
  #   secrets-dev rewrite PATH            scan + classify + propose ENV.fetch
  #   secrets-dev mcp                     start an MCP server on stdio
  #   secrets-dev login                   anonymous-token bootstrap
  #   secrets-dev whoami                  show current token + quota
  #   secrets-dev version
  class CLI < Thor
    def self.exit_on_failure? = true

    class_option :format, type: :string, default: 'pretty',
                 enum: %w[pretty json sarif],
                 desc: 'Output format'
    class_option :exclude, type: :array, default: [],
                 desc: 'Glob patterns to exclude (in addition to .gitignore)'
    class_option :only, type: :array, default: nil,
                 desc: 'Limit scan to these files (pre-commit hook mode)'
    class_option :show_fixtures, type: :boolean, default: false,
                 desc: 'Include FIXTURE-classified findings in output'

    desc 'scan PATH', 'Find candidate secrets in PATH (regex pre-filter only).'
    def scan(path = '.')
      findings = build_scanner(path).scan
      Reporter.new(format: options[:format], show_fixtures: options[:show_fixtures]).emit(findings)
      exit(Reporter.exit_code(findings))
    end

    desc 'verify PATH', 'Scan + offline-heuristic classify (no LLM call).'
    long_desc <<~DESC
      Runs `scan` and then applies offline heuristics (path hints, dummy-value
      markers, severity-by-path) to mark each candidate REAL / FIXTURE /
      UNKNOWN. Free and fast; the precision floor of the tool.

      For the AI-augmented classifier, run `secrets-dev mcp` and let your
      IDE / coding-agent host model do the reasoning.
    DESC
    def verify(path = '.')
      findings = build_scanner(path).scan
      Classifier.new(mode: :offline).classify(findings)
      Reporter.new(format: options[:format], show_fixtures: options[:show_fixtures]).emit(findings)
      exit(Reporter.exit_code(findings))
    end

    desc 'rewrite PATH', 'Scan + classify + propose ENV.fetch rewrites for REAL findings.'
    method_option :apply, type: :boolean, default: false,
                  desc: 'Actually apply the rewrites in-place (default: dry-run / show diff).'
    def rewrite(path = '.')
      findings = build_scanner(path).scan
      Classifier.new(mode: :offline).classify(findings)

      rewriter = Rewriter.new
      findings.select(&:real?).each do |f|
        f.replacement = rewriter.propose(f)
      end

      if options[:apply]
        apply_rewrites!(findings, scan_root: File.expand_path(path))
      end

      Reporter.new(format: options[:format], show_fixtures: false).emit(findings)
      exit(Reporter.exit_code(findings))
    end

    desc 'mcp', 'Start the MCP server on stdio for IDE / agent integration.'
    long_desc <<~DESC
      Speaks the Model Context Protocol over JSON-RPC on stdio. Exposes
      three tools (scan_repository, classify_candidates, propose_rewrite)
      and one prompt (the classifier system prompt). Hook this up to
      Claude Code via .mcp.json or to Cursor via the MCP settings.
    DESC
    def mcp
      require 'secrets_dev/mcp_server'
      MCPServer.new($stdin, $stdout).run
    end

    desc 'login', 'Issue a free anonymous token for the hosted classifier.'
    def login
      pastel = Pastel.new
      token = "sdv_anon_#{SecureRandom.hex(16)}"
      path = File.expand_path('~/.secrets-dev/config')
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, JSON.pretty_generate({ token: token, issued_at: Time.now.iso8601 }))
      File.chmod(0o600, path)
      puts pastel.green("✔ Wrote anonymous token to #{path}")
      puts pastel.dim('  (real backend not wired yet; token is locally generated for now)')
    end

    desc 'whoami', 'Show the active token and free-tier quota.'
    def whoami
      path = File.expand_path('~/.secrets-dev/config')
      unless File.file?(path)
        puts 'no token configured. run `secrets-dev login`.'
        exit 1
      end
      cfg = JSON.parse(File.read(path))
      puts "token: #{cfg['token'][0, 16]}...#{cfg['token'][-4..]}"
      puts "issued: #{cfg['issued_at']}"
    end

    desc 'version', 'Print version.'
    def version
      puts "secrets-dev #{SecretsDev::VERSION}"
    end

    private

    def build_scanner(path)
      Scanner.new(
        root: File.expand_path(path),
        extra_excludes: options[:exclude],
        only_paths: options[:only]&.map { |p| File.expand_path(p) },
      )
    end

    def apply_rewrites!(findings, scan_root:)
      grouped = findings.select { |f| f.real? && f.replacement }.group_by(&:path)
      grouped.each do |rel_path, group|
        absolute = File.join(scan_root, rel_path)
        next unless File.file?(absolute)

        lines = File.readlines(absolute, chomp: false)
        group.each do |f|
          idx = f.line - 1
          next unless lines[idx]&.include?(f.match)

          # Build the new line by substituting the secret with the replacement
          # call. Preserve the trailing \n.
          trailing = lines[idx].end_with?("\n") ? "\n" : ''
          lines[idx] = f.replacement.new_line + trailing
        end
        File.write(absolute, lines.join)
      end

      # Append to .env.example
      env_example = File.join(scan_root, '.env.example')
      env_lines = grouped.values.flatten.map { |f| f.replacement.env_example_line }.uniq
      if env_lines.any?
        existing = File.file?(env_example) ? File.read(env_example) : ''
        new_lines = env_lines.reject { |l| existing.include?(l.split('=').first) }
        if new_lines.any?
          File.open(env_example, 'a') do |io|
            io.puts unless existing.empty? || existing.end_with?("\n")
            io.puts '# Added by secrets-dev rewrite:'
            new_lines.each { |l| io.puts l }
          end
        end
      end
    end
  end
end
