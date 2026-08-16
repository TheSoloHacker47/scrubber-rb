# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-16

First release.

### Added

- **Rust scanning core** (magnus + rb-sys). Two-stage pass: one Aho-Corasick sweep over
  literal anchors to eliminate rules that cannot match, then one `RegexSet` pass for the rest.
  Overlaps resolved by leftmost, then most specific, then longest. Output built in a single
  walk rather than repeated `gsub`.
- **14 default detectors**: `email`, `phone`, `credit_card`, `ssn`, `iban`, `ip`, `ipv6`,
  `mac`, `jwt`, `aws_key`, `api_key`, `private_key`, `password_pair`, `url_credentials`.
- **Opt-in India pack** (`Scrubber::INDIA`): `phone_in`, `aadhaar`, `pan`, `upi`, for DPDP Act
  workloads.
- **Checksum validation**: Luhn for cards, Verhoeff for Aadhaar, ISO 7064 mod-97 for IBAN
  (plus an IBAN country-registry check), SSA range rules for SSNs, PAN entity-character check,
  and a PSP allowlist for UPI handles.
- **19 provider-specific API key formats** under `:api_key` — GitHub, GitLab, Slack, Stripe,
  OpenAI, Anthropic, Google, SendGrid, Twilio, npm, PyPI, Shopify, Square, Mailgun,
  DigitalOcean, Telegram, AWS secret keys. No entropy heuristics.
- **Four replacement strategies**: `:label`, `:mask`, `:hash` (salted, deterministic, so logs
  stay correlatable), `:remove`.
- **Custom detectors** from Ruby `Regexp`s, translated to Rust regex syntax. Backreferences,
  lookaround, atomic groups and possessive quantifiers raise
  `Scrubber::UnsupportedPatternError` at construction time, naming the construct — never
  silent partial coverage.
- **`Scrubber::LogFormatter`** — wraps any Logger formatter.
- **`Scrubber::Middleware`** — Rack middleware that publishes redacted copies of the query
  string and params at `env["scrubber.*"]` and redacts exception messages on the way out. It
  deliberately does not rewrite the live request.
- **`Scrubber::LLMGuard`** — a plain callable that redacts prompts, message arrays and message
  hashes before they reach a model API. Defaults to `:hash`.
- **`Scrubber.scrub_file`** — streams in 1MB chunks with an 8KB carry window, cutting at line
  boundaries, with an extra guard so multi-line PEM blocks are never split.
- **GVL released** for inputs over 64KB, so large scans don't stall other threads.
- **Panic hygiene**: every FFI entry point is wrapped in `catch_unwind`; a Rust panic becomes
  `Scrubber::InternalError` rather than a process abort.
- **Invalid UTF-8 tolerance**: valid regions are scrubbed, invalid bytes pass through
  unchanged, nothing raises.
- **Character-accurate offsets** from `Scrubber#detect`, so spans index the Ruby string
  correctly through emoji and Devanagari.
- **Benchmark suite** with an honest pure-Ruby reference implementing the identical detector
  set, a seeded 100MB corpus generator, and a spec asserting the two implementations redact
  identical spans.
- **Precompiled gems** for `x86_64-linux`, `x86_64-linux-musl`, `aarch64-linux`,
  `aarch64-linux-musl`, `x86_64-darwin`, `arm64-darwin`, plus a best-effort
  `x64-mingw-ucrt` and the source gem.

[Unreleased]: https://github.com/TheSoloHacker47/scrubber-rb/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TheSoloHacker47/scrubber-rb/releases/tag/v0.1.0
