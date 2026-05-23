# frozen_string_literal: true

require 'spec_helper'

RSpec.describe SecretsDev::Rewriter do
  def real_finding(path:, match:, context_line: nil)
    line = context_line || "FOO = '#{match}'"
    SecretsDev::Finding.new(
      path: path, line: 1, column: 1, match: match,
      pattern: :aws_access_key, severity: :high,
      context: ['# above', line, '# below'],
      verdict: :real, reason: 'test', confidence: 1.0, replacement: nil,
    )
  end

  describe '#propose' do
    it 'returns nil for non-real findings' do
      f = real_finding(path: 'app/x.rb', match: 'AKIAIOSFODNN7TESTABC')
      f.verdict = :unknown
      expect(described_class.new.propose(f)).to be_nil
    end

    it 'rewrites a Ruby constant assignment to ENV.fetch' do
      f = real_finding(
        path: 'app/services/aws.rb',
        match: 'AKIAIOSFODNN7TESTABC',
        context_line: "ACCESS_KEY = 'AKIAIOSFODNN7TESTABC'",
      )
      r = described_class.new.propose(f)
      expect(r.env_var).to eq('ACCESS_KEY')
      expect(r.new_line).to eq("ACCESS_KEY = ENV.fetch('ACCESS_KEY')")
      expect(r.env_example_line).to eq('ACCESS_KEY=')
    end

    it 'rewrites a JS const to process.env' do
      f = real_finding(
        path: 'src/aws.js',
        match: 'AKIAIOSFODNN7TESTABC',
        context_line: "const API_KEY = 'AKIAIOSFODNN7TESTABC';",
      )
      r = described_class.new.propose(f)
      expect(r.new_line).to include('process.env.API_KEY')
    end

    it 'rewrites a Python assignment to os.environ' do
      f = real_finding(
        path: 'src/aws.py',
        match: 'AKIAIOSFODNN7TESTABC',
        context_line: "API_KEY = 'AKIAIOSFODNN7TESTABC'",
      )
      r = described_class.new.propose(f)
      expect(r.new_line).to include("os.environ['API_KEY']")
    end

    it 'rewrites a Go assignment to os.Getenv' do
      f = real_finding(
        path: 'main.go',
        match: 'AKIAIOSFODNN7TESTABC',
        context_line: 'apiKey := "AKIAIOSFODNN7TESTABC"',
      )
      r = described_class.new.propose(f)
      expect(r.new_line).to include('os.Getenv("APIKEY")').or include('os.Getenv("apiKey")')
    end

    it 'emits seed commands for multiple secret backends' do
      f = real_finding(path: 'app/x.rb', match: 'AKIAIOSFODNN7TESTABC')
      r = described_class.new.propose(f)
      expect(r.seed_commands.join("\n")).to include('doppler', 'vault', 'aws secretsmanager')
    end

    it 'returns nil for unsupported file extensions' do
      f = real_finding(path: 'binary.bin', match: 'AKIAIOSFODNN7TESTABC')
      expect(described_class.new.propose(f)).to be_nil
    end
  end
end
