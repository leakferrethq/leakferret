# frozen_string_literal: true

require 'json'

module SecretsDev
  # Minimal MCP (Model Context Protocol) server speaking JSON-RPC 2.0 over
  # stdio. Implements the subset of the spec we need:
  #
  #   - initialize / initialized handshake
  #   - tools/list
  #   - tools/call         (scan_repository, classify_candidates, propose_rewrite)
  #   - prompts/list
  #   - prompts/get        (returns the classifier system prompt for the host LLM)
  #
  # Spec: https://spec.modelcontextprotocol.io
  #
  # We intentionally do NOT call any LLM here. The whole point of going
  # MCP-first is that the host agent's model reasons over the structured
  # candidate data we return from `classify_candidates`. The Ruby side is
  # data-only.
  class MCPServer
    PROTOCOL_VERSION = '2024-11-05'

    SERVER_INFO = {
      name: 'secrets-dev',
      version: SecretsDev::VERSION,
    }.freeze

    def initialize(input, output)
      @input = input
      @output = output
      @output.sync = true
    end

    def run
      while (line = @input.gets)
        line = line.strip
        next if line.empty?

        begin
          request = JSON.parse(line)
        rescue JSON::ParserError => e
          send_error(nil, -32_700, "Parse error: #{e.message}")
          next
        end

        handle(request)
      end
    end

    private

    def handle(request)
      id = request['id']
      method = request['method']
      params = request['params'] || {}

      case method
      when 'initialize'                    then handle_initialize(id, params)
      when 'initialized', 'notifications/initialized' then nil # no-op
      when 'tools/list'                    then handle_tools_list(id)
      when 'tools/call'                    then handle_tools_call(id, params)
      when 'prompts/list'                  then handle_prompts_list(id)
      when 'prompts/get'                   then handle_prompts_get(id, params)
      when 'ping'                          then send_result(id, {})
      else
        send_error(id, -32_601, "Method not found: #{method}") if id
      end
    rescue StandardError => e
      send_error(id, -32_603, "Internal error: #{e.class}: #{e.message}") if id
    end

    def handle_initialize(id, _params)
      send_result(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          tools: { listChanged: false },
          prompts: { listChanged: false },
        },
        serverInfo: SERVER_INFO,
      })
    end

    TOOLS = [
      {
        name: 'scan_repository',
        description: <<~DESC.strip,
          Walks a directory tree and returns candidate secrets found via regex
          pre-filter. Verdict is :unknown — call classify_candidates next, or
          use the system prompt at prompts/get to classify in-conversation.
        DESC
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Absolute or relative path to scan.' },
            exclude: { type: 'array', items: { type: 'string' }, default: [] },
          },
          required: ['path'],
        },
      },
      {
        name: 'classify_candidates',
        description: <<~DESC.strip,
          Apply offline heuristic classification to the candidates returned
          from scan_repository. Returns the same candidates with verdict /
          reason / confidence filled in. For higher accuracy, prefer to ask
          the host model to classify directly using the prompt available at
          prompts/get name=classify.
        DESC
        inputSchema: {
          type: 'object',
          properties: {
            candidates: { type: 'array', items: { type: 'object' } },
          },
          required: ['candidates'],
        },
      },
      {
        name: 'propose_rewrite',
        description: <<~DESC.strip,
          For a finding classified REAL, propose a code edit that swaps the
          hardcoded secret for an env-var lookup in the file's language,
          plus a .env.example entry, plus seed commands for Vault / Doppler
          / AWS Secrets Manager. Never stores or transmits the secret value.
        DESC
        inputSchema: {
          type: 'object',
          properties: {
            finding: { type: 'object' },
          },
          required: ['finding'],
        },
      },
    ].freeze

    def handle_tools_list(id)
      send_result(id, { tools: TOOLS })
    end

    def handle_tools_call(id, params)
      name = params['name']
      args = params['arguments'] || {}

      result =
        case name
        when 'scan_repository'     then tool_scan(args)
        when 'classify_candidates' then tool_classify(args)
        when 'propose_rewrite'     then tool_rewrite(args)
        else
          return send_error(id, -32_602, "Unknown tool: #{name}")
        end

      send_result(id, {
        content: [{ type: 'text', text: JSON.pretty_generate(result) }],
      })
    end

    PROMPTS = [
      {
        name: 'classify',
        description: 'System prompt for classifying candidate secrets as REAL / FIXTURE / UNKNOWN.',
      },
    ].freeze

    def handle_prompts_list(id)
      send_result(id, { prompts: PROMPTS })
    end

    def handle_prompts_get(id, params)
      name = params['name']
      case name
      when 'classify'
        send_result(id, {
          description: PROMPTS.first[:description],
          messages: [{
            role: 'system',
            content: { type: 'text', text: Classifier::SYSTEM_PROMPT },
          }],
        })
      else
        send_error(id, -32_602, "Unknown prompt: #{name}")
      end
    end

    # --- Tool implementations ---

    def tool_scan(args)
      path = args.fetch('path')
      exclude = args.fetch('exclude', [])
      findings = Scanner.new(root: File.expand_path(path), extra_excludes: exclude).scan
      { candidates: findings.map { |f| serialize_finding(f) } }
    end

    def tool_classify(args)
      candidates = args.fetch('candidates')
      findings = candidates.map { |h| hydrate_finding(h) }
      Classifier.new(mode: :offline).classify(findings)
      { candidates: findings.map { |f| serialize_finding(f) } }
    end

    def tool_rewrite(args)
      finding = hydrate_finding(args.fetch('finding'))
      finding.verdict = :real # force-real for rewrite tool — caller asked.
      replacement = Rewriter.new.propose(finding)
      return { error: 'unsupported language or no safe rewrite available' } if replacement.nil?

      {
        env_var: replacement.env_var,
        old_line: replacement.old_line,
        new_line: replacement.new_line,
        env_example_line: replacement.env_example_line,
        seed_commands: replacement.seed_commands,
      }
    end

    def serialize_finding(f)
      {
        path: f.path,
        line: f.line,
        column: f.column,
        pattern: f.pattern.to_s,
        severity: f.severity.to_s,
        match_redacted: f.redacted_match,
        context: f.context,
        verdict: f.verdict.to_s,
        reason: f.reason,
        confidence: f.confidence,
      }
    end

    def hydrate_finding(h)
      Finding.new(
        path: h['path'],
        line: h['line'],
        column: h['column'],
        match: h['match'] || h['match_redacted'], # if only redacted available, rewriter can't run
        pattern: (h['pattern'] || 'unknown').to_sym,
        severity: (h['severity'] || 'unknown').to_sym,
        context: h['context'] || [],
        verdict: (h['verdict'] || 'unknown').to_sym,
        reason: h['reason'],
        confidence: h['confidence'],
        replacement: nil,
      )
    end

    # --- JSON-RPC helpers ---

    def send_result(id, result)
      write({ jsonrpc: '2.0', id: id, result: result })
    end

    def send_error(id, code, message)
      write({ jsonrpc: '2.0', id: id, error: { code: code, message: message } })
    end

    def write(obj)
      @output.puts JSON.generate(obj)
    end
  end
end
