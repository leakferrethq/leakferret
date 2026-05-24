# Contributing

Thanks for considering a contribution.

## Local development

```bash
git clone https://github.com/leakferrethq/leakferret
cd leakferret
bundle install
bundle exec rspec
bundle exec rubocop
```

To exercise the CLI without a `gem install`:

```bash
ruby -Ilib bin/leakferret scan path/to/somewhere
```

## What I'd love help with

- **More language support in `Rewriter`.** Currently Ruby, JS/TS, Python,
  Go, Java, Shell, YAML. Rust / Kotlin / Scala / PHP welcome.
- **Real ripgrep fallback in `Scanner`.** Shell out to `rg --json` when
  `rg` is on `$PATH`. Same `Finding` output.
- **More regex patterns in `Patterns`.** Each one should include a tight
  enough regex that the false-positive rate is moderate.
- **VS Code extension polish.** Diagnostics + Quick Fix work; the
  "Replace with ENV.fetch" command wiring is stubbed.

## Code style

- RuboCop config is in `.rubocop.yml`. Run `bundle exec rubocop -a` to
  auto-fix what it knows about.
- Public methods get a top comment. Avoid trailing-explanation comments.
- New features need RSpec coverage of the happy path + one edge case.

## Security

If you find a vulnerability in `leakferret` itself, please don't open a
public issue. Email `maria@runbookpages.com`.

## License

MIT (see `LICENSE.txt`). Contributions are accepted under the same.
