# frozen_string_literal: true

# Top-level namespace. Sub-files are explicitly required (no Zeitwerk) so the
# library boots fast even when only one component is needed (e.g. the CLI
# wants Reporter but not the MCPServer or vice versa).
module SecretsDev
  class Error < StandardError; end
end

require 'securerandom'

require 'secrets_dev/version'
require 'secrets_dev/finding'
require 'secrets_dev/patterns'
require 'secrets_dev/gitignore'
require 'secrets_dev/scanner'
require 'secrets_dev/classifier'
require 'secrets_dev/rewriter'
require 'secrets_dev/reporter'
# MCPServer is required lazily by CLI#mcp so we don't pay its boot cost on
# every CLI invocation.
