# frozen_string_literal: true

require 'spec_helper'
require 'secrets_dev/mcp_server'
require 'stringio'
require 'tmpdir'
require 'fileutils'
require 'json'

RSpec.describe SecretsDev::MCPServer do
  def jsonrpc(method, params = {}, id: 1)
    JSON.generate({ jsonrpc: '2.0', id: id, method: method, params: params })
  end

  def run_server_with(*lines)
    input = StringIO.new(lines.join("\n") + "\n")
    output = StringIO.new
    described_class.new(input, output).run
    output.string.each_line.map { |l| JSON.parse(l) }
  end

  it 'responds to initialize with protocol version + server info' do
    responses = run_server_with(jsonrpc('initialize', { protocolVersion: '2024-11-05' }))
    expect(responses.first['result']['protocolVersion']).to eq('2024-11-05')
    expect(responses.first['result']['serverInfo']['name']).to eq('secrets-dev')
  end

  it 'lists three tools' do
    responses = run_server_with(jsonrpc('tools/list', {}, id: 2))
    names = responses.first['result']['tools'].map { |t| t['name'] }
    expect(names).to contain_exactly('scan_repository', 'classify_candidates', 'propose_rewrite')
  end

  it 'returns the classify prompt at prompts/get' do
    responses = run_server_with(jsonrpc('prompts/get', { name: 'classify' }, id: 3))
    text = responses.first['result']['messages'].first['content']['text']
    expect(text).to include('REAL')
    expect(text).to include('FIXTURE')
  end

  it 'errors on unknown method' do
    responses = run_server_with(jsonrpc('nonsense', {}, id: 9))
    expect(responses.first['error']['code']).to eq(-32_601)
  end

  it 'runs scan_repository as a tool call' do
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p(File.join(dir, 'app'))
      File.write(File.join(dir, 'app', 'x.rb'), "K = 'AKIAIOSFODNN7TESTABCD'\n")

      responses = run_server_with(jsonrpc(
        'tools/call',
        { name: 'scan_repository', arguments: { path: dir } },
        id: 4,
      ))
      payload = JSON.parse(responses.first['result']['content'].first['text'])
      expect(payload['candidates'].size).to eq(1)
      expect(payload['candidates'].first['pattern']).to eq('aws_access_key')
      expect(payload['candidates'].first).not_to have_key('match') # redacted only
    end
  end
end
