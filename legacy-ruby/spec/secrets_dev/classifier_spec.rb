# frozen_string_literal: true

require 'spec_helper'

RSpec.describe SecretsDev::Classifier do
  def finding(path: 'app/services/x.rb', pattern: :aws_access_key, severity: :high,
              match: 'AKIAIOSFODNN7EXAMPLE', context: ["K = 'AKIAIOSFODNN7EXAMPLE'"])
    SecretsDev::Finding.new(
      path: path, line: 1, column: 1, match: match, pattern: pattern,
      severity: severity, context: context, verdict: :unknown,
      reason: nil, confidence: nil, replacement: nil,
    )
  end

  describe '#classify (offline)' do
    subject(:classifier) { described_class.new(mode: :offline) }

    it 'marks app-path + high-sev as REAL' do
      f = finding(path: 'app/services/aws_client.rb')
      classifier.classify([f])
      expect(f.verdict).to eq(:real)
      expect(f.reason).to include('application path')
    end

    it 'marks spec-path as FIXTURE' do
      f = finding(path: 'spec/services/aws_client_spec.rb')
      classifier.classify([f])
      expect(f.verdict).to eq(:fixture)
    end

    it 'marks fixtures/ as FIXTURE' do
      f = finding(path: 'spec/fixtures/aws.json')
      classifier.classify([f])
      expect(f.verdict).to eq(:fixture)
    end

    it 'marks docs/ as FIXTURE' do
      f = finding(path: 'docs/example.md')
      classifier.classify([f])
      expect(f.verdict).to eq(:fixture)
    end

    it 'marks AKIA...EXAMPLE as FIXTURE regardless of path' do
      f = finding(path: 'app/lib/x.rb', match: 'AKIAIOSFODNN7EXAMPLE')
      classifier.classify([f])
      expect(f.verdict).to eq(:fixture)
    end

    it 'leaves ambiguous cases as UNKNOWN' do
      f = finding(path: 'scripts/run.rb', match: 'AKIA1234567890ABCDEF', severity: :unknown)
      classifier.classify([f])
      expect(f.verdict).to eq(:unknown)
    end
  end

  describe '#serialize_for_host' do
    it 'returns a payload with prompt + per-finding redacted candidates' do
      f = finding
      payload = described_class.new.serialize_for_host([f])
      expect(payload[:system]).to include('REAL')
      expect(payload[:candidates].first[:match_redacted]).to eq('AKIA...MPLE')
      expect(payload[:candidates].first[:match_redacted]).not_to include('IOSFODNN7')
    end
  end

  describe '#apply_verdicts!' do
    it 'writes LLM-shaped responses back onto findings' do
      f = finding
      classifier = described_class.new
      response = [{ 'id' => '0', 'verdict' => 'REAL', 'reason' => 'looks live', 'confidence' => 0.9 }]
      classifier.apply_verdicts!([f], response)
      expect(f.verdict).to eq(:real)
      expect(f.reason).to eq('looks live')
      expect(f.confidence).to eq(0.9)
    end

    it 'falls back to :unknown for unrecognized verdicts' do
      f = finding
      described_class.new.apply_verdicts!([f], [{ 'id' => '0', 'verdict' => 'MAYBE' }])
      expect(f.verdict).to eq(:unknown)
    end
  end
end
