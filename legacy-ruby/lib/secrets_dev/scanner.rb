# frozen_string_literal: true

require 'find'

module SecretsDev
  # Walks a directory tree, runs each text file against Patterns, returns
  # a flat list of Findings.
  #
  # Performance plan:
  #   v0 (today)    pure Ruby walk + Regexp.scan per line. Fast enough for
  #                 repos up to ~100k files; slow on monorepos.
  #   v1 (later)    swap inner loop for a `ripgrep --json` shellout when rg
  #                 is on $PATH. Same Finding output, ~50-100x faster.
  class Scanner
    # File extensions worth scanning. Binary/asset extensions are always
    # skipped regardless. `.env*` files (no extension after the dot) are
    # special-cased because they're a common leak source.
    DEFAULT_INCLUDE_EXT = %w[
      .rb .erb .py .js .ts .tsx .jsx .mjs .cjs .vue .svelte
      .go .java .kt .scala .rs .ex .exs .ml .clj .cljs .php
      .sh .bash .zsh .fish .pl .lua .swift .c .cc .cpp .h .hpp
      .yml .yaml .toml .json .json5 .ini .conf .properties .xml
      .tf .tfvars .hcl .nomad
      .md .mdx .txt .rst
      .gradle .groovy .dockerfile .containerfile
    ].freeze

    CONTEXT_LINES = 3
    MAX_FILE_BYTES = 2 * 1024 * 1024 # skip files >2MB; almost never source

    def initialize(root:, extra_excludes: [], include_ext: DEFAULT_INCLUDE_EXT, only_paths: nil)
      @root = File.expand_path(root)
      @ignore = Gitignore.new(root: @root, extra_excludes: extra_excludes)
      @include_ext = include_ext
      @only_paths = only_paths # nil = all files; array = only these absolute paths
    end

    def scan
      findings = []
      walk do |abs_path|
        next if @only_paths && !@only_paths.include?(abs_path)
        next if binary_or_skipped?(abs_path)

        scan_file(abs_path).each { |f| findings << f }
      end
      findings
    end

    private

    def walk
      Find.find(@root) do |path|
        if File.directory?(path)
          if path != @root && @ignore.ignore?(path, directory: true)
            Find.prune
          end
          next
        end
        next if @ignore.ignore?(path, directory: false)

        yield path
      end
    end

    def binary_or_skipped?(path)
      basename = File.basename(path)
      ext = File.extname(path).downcase

      # .env / .env.local / .env.production — special-cased
      return false if basename.start_with?('.env')

      return true if ext.empty?
      return true unless @include_ext.include?(ext)

      begin
        return true if File.size(path) > MAX_FILE_BYTES
        # Cheap binary sniff: NUL byte in first 8KB
        File.open(path, 'rb') { |io| io.read(8 * 1024) }.include?("\0")
      rescue SystemCallError
        true
      end
    end

    def scan_file(path)
      rel = relative(path)
      findings = []
      lines = File.readlines(path, chomp: false)
      lines.each_with_index do |line, idx|
        Patterns.all.each do |pattern|
          line.scan(pattern[:regex]) do |captures|
            captures = [captures].flatten
            match = captures.first || Regexp.last_match[0]
            next if match.nil? || match.empty?

            findings << Finding.new(
              path: rel,
              line: idx + 1,
              column: (Regexp.last_match&.begin(0) || 0) + 1,
              match: match,
              pattern: pattern[:name],
              severity: pattern[:severity] || :unknown,
              context: context_window(lines, idx),
              verdict: :unknown,
              reason: nil,
              confidence: nil,
              replacement: nil,
            )
          end
        end
      end
      findings
    rescue StandardError
      # Unreadable file — skip. Surface under `--strict` later.
      []
    end

    def context_window(lines, idx)
      start_idx = [idx - CONTEXT_LINES, 0].max
      end_idx   = [idx + CONTEXT_LINES, lines.length - 1].min
      lines[start_idx..end_idx].map(&:chomp)
    end

    def relative(absolute)
      absolute.sub(/^#{Regexp.escape(@root)}\/?/, '')
    end
  end
end
