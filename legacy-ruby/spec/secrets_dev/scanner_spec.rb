# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe SecretsDev::Scanner do
  around do |example|
    Dir.mktmpdir do |dir|
      @root = dir
      example.run
    end
  end

  def write(rel, content)
    full = File.join(@root, rel)
    FileUtils.mkdir_p(File.dirname(full))
    File.write(full, content)
    full
  end

  describe '#scan' do
    it 'returns no findings for a clean file' do
      write('app/lib/util.rb', "def hello\n  'world'\nend\n")
      expect(described_class.new(root: @root).scan).to be_empty
    end

    it 'finds an AWS access key with the right structure' do
      write('app/services/aws_client.rb', <<~RUBY)
        class AwsClient
          ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
        end
      RUBY
      findings = described_class.new(root: @root).scan
      expect(findings.size).to eq(1)
      expect(findings.first.pattern).to eq(:aws_access_key)
      expect(findings.first.path).to eq('app/services/aws_client.rb')
      expect(findings.first.severity).to eq(:high)
    end

    it 'finds a Stripe live secret and tags it critical' do
      write('config/stripe.rb', "Stripe.api_key = 'sk_live_abc123def456ghi789jkl012'\n")
      findings = described_class.new(root: @root).scan
      expect(findings.size).to eq(1)
      expect(findings.first.pattern).to eq(:stripe_secret)
      expect(findings.first.severity).to eq(:critical)
    end

    it 'finds GitHub PAT prefixes' do
      write('lib/gh.rb', "TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n")
      findings = described_class.new(root: @root).scan
      expect(findings.map(&:pattern)).to include(:github_token)
    end

    it 'finds an OpenAI key' do
      write('lib/openai.rb', "OPENAI_API_KEY = 'sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD'\n")
      findings = described_class.new(root: @root).scan
      expect(findings.map(&:pattern)).to include(:openai_key)
    end

    it 'finds a postgres URL with credentials' do
      write('config/db.yml', "database_url: postgres://user:hunter2@db.host.com:5432/prod\n")
      findings = described_class.new(root: @root).scan
      expect(findings.map(&:pattern)).to include(:postgres_url)
    end

    it 'redacts the match in to_h_safe' do
      write('lib/x.rb', "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
      findings = described_class.new(root: @root).scan
      expect(findings.first.to_h_safe[:match_redacted]).to eq('AKIA...MPLE')
      expect(findings.first.to_h_safe[:match_redacted]).not_to include('IOSFODNN7')
    end

    it 'builds a stable cache_key per finding' do
      write('lib/x.rb', "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
      a = described_class.new(root: @root).scan.first
      b = described_class.new(root: @root).scan.first
      expect(a.cache_key).to eq(b.cache_key)
    end

    it 'excludes the node_modules directory by default' do
      write('node_modules/foo.js', "const k = 'AKIAIOSFODNN7EXAMPLE';\n")
      write('app/foo.rb',          "k = 'AKIAIOSFODNN7EXAMPLE'\n")
      paths = described_class.new(root: @root).scan.map(&:path)
      expect(paths).to include('app/foo.rb')
      expect(paths).not_to(be_any { |p| p.start_with?('node_modules') })
    end

    it 'respects a .gitignore at the root' do
      write('.gitignore', "secret.rb\n")
      write('secret.rb',  "K = 'AKIAIOSFODNN7EXAMPLE'\n")
      write('app/x.rb',   "K = 'AKIAIOSFODNN7EXAMPLE'\n")
      paths = described_class.new(root: @root).scan.map(&:path)
      expect(paths).not_to include('secret.rb')
      expect(paths).to include('app/x.rb')
    end

    it 'honors the only_paths filter for incremental scans' do
      a = write('app/a.rb', "K = 'AKIAIOSFODNN7EXAMPLE'\n")
      _b = write('app/b.rb', "K = 'AKIAIOSFODNN7EXAMPLE'\n")
      paths = described_class.new(root: @root, only_paths: [a]).scan.map(&:path)
      expect(paths).to eq(['app/a.rb'])
    end

    it 'skips binary files via the NUL-byte sniff' do
      write('app/blob.rb', "K = 'AKIAIOSFODNN7EXAMPLE'\nthen\x00binary\n")
      expect(described_class.new(root: @root).scan).to be_empty
    end

    it 'scans .env files even without a recognised extension' do
      write('.env.production', "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz0123456789ABCD\n")
      findings = described_class.new(root: @root).scan
      expect(findings.map(&:pattern)).to include(:aws_secret_key)
    end

    it 'captures context lines around the match' do
      write('lib/x.rb', "line1\nline2\nK = 'AKIAIOSFODNN7EXAMPLE'\nline4\nline5\n")
      finding = described_class.new(root: @root).scan.first
      expect(finding.context).to include("K = 'AKIAIOSFODNN7EXAMPLE'")
      expect(finding.context.first).to include('line') # 3 above
      expect(finding.context.last).to  include('line') # 3 below
    end
  end
end
