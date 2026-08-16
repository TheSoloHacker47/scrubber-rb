# Contributing to scrubber_rb

Thanks for helping. This is a security-adjacent library, so the bar for "correct" is a bit
higher than usual: a false negative here means somebody's customer data ends up in a log
aggregator.

## Setup

```bash
git clone https://github.com/TheSoloHacker47/scrubber-rb && cd scrubber-rb
bin/setup
```

`bin/setup` runs `bundle install` and `rake compile`. It will tell you how to install a Rust
toolchain if you don't have one, but it won't install one behind your back.

## The loop

```bash
bundle exec rake              # compile + spec
bundle exec rake ci           # everything CI runs, in CI's order
bundle exec rake cargo:test   # just the Rust unit tests
bin/console                   # irb with the gem loaded
```

`cargo test` needs `--features link-ruby` so the test binary can link libruby; the
`cargo:test` rake task passes it for you.

## Where code goes

| You are changing | It lives in |
|---|---|
| A detector pattern, priority or anchor | `ext/scrubber_rb/src/detectors/mod.rs` |
| A checksum (Luhn, Verhoeff, mod-97) | `ext/scrubber_rb/src/detectors/checksum.rs` |
| A post-match validity check | `ext/scrubber_rb/src/detectors/validate.rs` |
| Scanning, overlap resolution, output building | `ext/scrubber_rb/src/engine.rs` |
| A replacement strategy | `ext/scrubber_rb/src/replace.rs` |
| Ruby-regex translation | `ext/scrubber_rb/src/pattern.rs` |
| Anything touching a Ruby `VALUE` | `ext/scrubber_rb/src/lib.rs` — and nowhere else |
| Public Ruby API, integrations | `lib/` |

Keeping Ruby out of everything below `lib.rs` is what makes the engine testable with plain
`cargo test` and safe to run with the GVL released. Please don't leak `magnus` types downward.

## Proposing a new detector

New detectors are welcome. A PR should include:

1. **Public test vectors.** Numbers or keys the vendor publishes precisely so they can appear
   in test suites. Do not use a real credential, yours or anyone else's. If the format has a
   checksum, *generate* the vectors in the test rather than pasting them, so two wrong numbers
   can't agree with each other (see `spec/support/vectors.rb`).
2. **A false-positive analysis.** What else in a normal log has this shape? Run the detector
   over `benchmark/corpus/production.log` and the `spec/fixtures/` files and say what it hits.
   `spec/fixtures_spec.rb` has a "false positives on ordinary application logs" example — add
   to it.
3. **A checksum or a context check, if one exists.** `\d{16}` is not a credit card detector;
   `\d{16}` plus Luhn is. This is the difference the gem is built around.
4. **A matching rule in `benchmark/pure_ruby_reference.rb`.** The benchmark's honesty depends
   on both implementations doing the same work, and `spec/benchmark_reference_spec.rb`
   enforces it.
5. **An anchor, if the pattern has a required literal.** Anchors go in the Aho-Corasick
   prefilter and are how the engine skips rules cheaply. Use only literals of 3+ characters —
   a one-character anchor filters nothing and just adds work. If in doubt, leave `anchors`
   empty; that is always correct, just slower.

Region packs (like `Scrubber::INDIA`) are opt-in, never in `DEFAULTS`. A detector that fires
on data most users don't have is a false-positive source for them.

## Things that will get a PR sent back

- A pattern that needs backtracking. The linear-time guarantee is a feature, not an accident.
- A change to the public API without a discussion first — see the frozen surface in the README.
- A detector with no checksum where the format has one.
- Making the benchmark faster by making the pure-Ruby reference worse.
- Reducing what `:mask` hides for a secret. Last-four of an API key is a leak.

## Style

- Rust: `cargo fmt`, `cargo clippy -- -D warnings`. Both are CI gates.
- Ruby: `rubocop`. Also a CI gate.
- Comments explain *why*, not *what*. If a line looks wrong but is right, say why it's right.

## Reporting a bug

Please use the issue template. It asks for `Scrubber::VERSION`, whether you're on a platform
gem or a source build, and a minimal input string.

**Redact the input string first.** You know a good tool for that.

## Security issues

Don't open a public issue. See [SECURITY.md](SECURITY.md).
