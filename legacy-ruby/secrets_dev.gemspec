require_relative 'lib/secrets_dev/version'

Gem::Specification.new do |spec|
  spec.name        = 'secrets_dev'
  spec.version     = SecretsDev::VERSION
  spec.authors     = ['Maria Khan']
  spec.email       = ['maria@runbookpages.com']

  spec.summary     = 'AI-context-aware secret detection and rewriting.'
  spec.description = <<~DESC
    Finds real secrets in your codebase — not the test-fixture noise that
    gitleaks and trufflehog flag and you ignore. Uses an LLM to classify
    candidates in context, and can rewrite call sites to pull from ENV
    (or Vault / Doppler / AWS Secrets Manager).
  DESC
  spec.homepage    = 'https://github.com/leakferrethq/secrets-dev'
  spec.license     = 'MIT'

  spec.required_ruby_version = '>= 3.1.0'

  spec.metadata['homepage_uri']    = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri']   = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir.glob(%w[
    lib/**/*.rb
    bin/*
    README.md
    LICENSE.txt
  ])
  spec.bindir      = 'bin'
  spec.executables = ['secrets-dev']
  spec.require_paths = ['lib']

  # Runtime deps — kept minimal on purpose.
  spec.add_dependency 'thor', '~> 1.3'    # CLI subcommands
  spec.add_dependency 'pastel', '~> 0.8'  # terminal coloring
end
