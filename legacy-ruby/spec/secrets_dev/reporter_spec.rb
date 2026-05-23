# frozen_string_literal: true

require 'spec_helper'
require 'stringio'
require 'json'

RSpec.describe SecretsDev::Reporter do
  def finding(verdict:, severity: :high, path: 'app/x.rb', match: 'AKIAIOSFODNN7TESTABC')
    SecretsDev::Finding.new(
      path: path, line: 12, column: 5, match: match,
      pattern: :aws_access_key, severity: severity,
      context: ["K = '#{match}'"], verdict: verdict,
      reason: 'test reason', confidence: 0.8, replacement: nil,
    )
  end

  describe 'pretty format' do
    it 'shows ✔ when there are no findings' do
      io = StringIO.new
      described_class.new(format: 'pretty', stream: io).emit([])
      expect(io.string).to include('no candidate secrets found')
    end

    it 'hides FIXTURE findings by default' do
      io = StringIO.new
      described_class.new(format: 'pretty', stream: io).emit([finding(verdict: :fixture)])
      expect(io.string).to include('no candidate secrets found')
    end

    it 'shows FIXTURE findings when show_fixtures=true' do
      io = StringIO.new
      described_class.new(format: 'pretty', stream: io, show_fixtures: true).emit([finding(verdict: :fixture)])
      expect(io.string).to include('FIXTURE')
    end
  end

  describe 'json format' do
    it 'emits the to_h_safe array' do
      io = StringIO.new
      described_class.new(format: 'json', stream: io).emit([finding(verdict: :real)])
      parsed = JSON.parse(io.string)
      expect(parsed.size).to eq(1)
      expect(parsed.first['verdict']).to eq('real')
      expect(parsed.first['match_redacted']).to eq('AKIA...TABC')
      expect(parsed.first).not_to have_key('match')
    end
  end

  describe 'sarif format' do
    it 'emits a valid SARIF 2.1.0 document with results' do
      io = StringIO.new
      described_class.new(format: 'sarif', stream: io).emit([finding(verdict: :real)])
      parsed = JSON.parse(io.string)
      expect(parsed['version']).to eq('2.1.0')
      expect(parsed['runs'].first['tool']['driver']['name']).to eq('secrets-dev')
      expect(parsed['runs'].first['results'].first['ruleId']).to eq('aws_access_key')
      expect(parsed['runs'].first['results'].first['level']).to eq('error')
    end

    it 'downgrades FIXTURE findings to note level' do
      io = StringIO.new
      described_class.new(format: 'sarif', stream: io, show_fixtures: true)
                     .emit([finding(verdict: :fixture)])
      parsed = JSON.parse(io.string)
      expect(parsed['runs'].first['results'].first['level']).to eq('note')
    end
  end

  describe '.exit_code' do
    it 'is 1 when any finding is REAL' do
      expect(described_class.exit_code([finding(verdict: :real)])).to eq(1)
    end

    it 'is 0 when no findings are REAL' do
      expect(described_class.exit_code([finding(verdict: :fixture), finding(verdict: :unknown)])).to eq(0)
    end
  end
end
