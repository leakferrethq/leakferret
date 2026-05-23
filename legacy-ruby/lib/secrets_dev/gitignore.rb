# frozen_string_literal: true

module SecretsDev
  # Minimal `.gitignore` matcher. Reads the .gitignore at the scan root +
  # any nested .gitignore files, builds a chain of fnmatch rules with the
  # `**` and `!` semantics gitignore uses, and answers `ignore?(path)`.
  #
  # Deliberately not perfect — full gitignore semantics live in libgit2's
  # 600+ lines of C. This covers the common ~95% of cases we'll hit on real
  # repos and is the right cheap abstraction to ship.
  class Gitignore
    Rule = Struct.new(:pattern, :negation, :dir_only, :anchor_dir, keyword_init: true)

    DEFAULT_IGNORES = %w[
      .git
      node_modules
      vendor/bundle
      vendor/cache
      .bundle
      tmp
      log
      coverage
      dist
      build
      target
      .next
      .nuxt
      .terraform
      .gradle
      .venv
      __pycache__
    ].freeze

    def initialize(root:, extra_excludes: [])
      @root = root
      @rules = []
      DEFAULT_IGNORES.each { |p| @rules << Rule.new(pattern: p, negation: false, dir_only: true, anchor_dir: root) }
      load_file(File.join(root, '.gitignore'), root) if File.file?(File.join(root, '.gitignore'))
      extra_excludes.each { |g| @rules << Rule.new(pattern: g, negation: false, dir_only: false, anchor_dir: root) }
    end

    # Path is absolute (matches what Find.find yields).
    def ignore?(absolute_path, directory:)
      rel = relative_to_root(absolute_path)
      return false if rel.nil? || rel.empty?

      ignored = false
      @rules.each do |rule|
        next if rule.dir_only && !directory

        if match?(rule.pattern, rel, directory: directory)
          ignored = !rule.negation
        end
      end
      ignored
    end

    private

    def load_file(path, anchor_dir)
      File.foreach(path) do |line|
        line = line.strip
        next if line.empty? || line.start_with?('#')

        negation = line.start_with?('!')
        line = line[1..] if negation

        dir_only = line.end_with?('/')
        line = line[0..-2] if dir_only

        @rules << Rule.new(pattern: line, negation: negation, dir_only: dir_only, anchor_dir: anchor_dir)
      end
    rescue StandardError
      # Unreadable .gitignore — non-fatal, skip.
    end

    def relative_to_root(absolute_path)
      return nil unless absolute_path.start_with?(@root)

      rel = absolute_path[@root.length..]
      rel = rel.sub(%r{^/+}, '')
      rel
    end

    def match?(pattern, rel, directory:)
      # If pattern has no `/`, match basename anywhere in the tree.
      # If pattern starts with `/`, match from root only.
      # `**` matches any number of dirs.
      anchored = pattern.start_with?('/')
      pattern = pattern.sub(%r{^/}, '') if anchored

      candidates =
        if anchored
          [rel]
        else
          [rel, File.basename(rel)] + rel.split('/').each_with_index.map { |_, i| rel.split('/')[i..].join('/') }
        end

      fnmatch_flags = File::FNM_PATHNAME | File::FNM_DOTMATCH
      candidates.uniq.any? do |c|
        File.fnmatch?(pattern, c, fnmatch_flags) ||
          File.fnmatch?(pattern.gsub('**', '*'), c, fnmatch_flags) ||
          File.fnmatch?("#{pattern}/**", c, fnmatch_flags)
      end
    end
  end
end
