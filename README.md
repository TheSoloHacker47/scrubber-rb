# scrubber_rb

> Fast PII & secret redaction for Ruby — Rust-cored. Scrub logs, LLM prompts, and payloads before they leak.

[![Gem Version](https://badge.fury.io/rb/scrubber_rb.svg)](https://rubygems.org/gems/scrubber_rb)
[![CI](https://github.com/TheSoloHacker47/scrubber-rb/actions/workflows/ci.yml/badge.svg)](https://github.com/TheSoloHacker47/scrubber-rb/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Your production logs contain emails. Your error tracker captures request params with credit
cards in them. And now your app pipes user content straight into LLM APIs. `scrubber_rb`
redacts sensitive data from any string in a single pass through a Rust engine — fast enough
to sit in your logger, your Rack stack, and in front of every AI call.

```ruby
Scrubber.scrub("contact nik@example.com, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE")
# => "contact [EMAIL], card [CREDIT_CARD], key [AWS_KEY]"
```

## Why this gem

- **Fast.** Multi-pattern scanning runs in Rust (`regex` + `aho-corasick`) — one pass, no
  backtracking, GVL released on large inputs. Measured **38x** a pure-Ruby implementation of
  the identical detector set on a 100MB log corpus, and **83x** on a single log line
  ([methodology below](#benchmarks), reproducible via `rake benchmark`).
- **Accurate.** Checksums, not just shapes: credit cards must pass Luhn, Aadhaar must pass
  Verhoeff, IBANs must pass mod-97. A random 16-digit number won't get redacted.
- **Complete.** 18 detectors out of the box — emails, phones, cards, SSNs, IBANs, IPs, MACs,
  JWTs, AWS keys, 19 provider-specific API key formats, private key blocks, `password=` pairs,
  URL credentials — plus an opt-in India pack (Aadhaar, PAN, UPI) for DPDP Act compliance.
- **ReDoS-immune.** Rust's regex engine is linear-time by design, so attacker-controlled log
  content can't blow up your CPU with pathological backtracking.
- **No toolchain needed.** Precompiled gems for Linux (x86_64/aarch64, glibc & musl) and
  macOS (Intel & Apple Silicon). `gem install scrubber_rb` and you're done.

## Installation

```ruby
# Gemfile
gem "scrubber_rb"
```

Requires Ruby >= 3.1. If no precompiled gem matches your platform, the source gem builds
automatically (needs a Rust toolchain).

## Usage

### Basic

```ruby
Scrubber.scrub(text)     # default detectors, [LABEL] replacement
Scrubber.detect(text)    # => [#<Scrubber::Match type=:email 11...26 preview="n**@e******.com">]
Scrubber.match?(text)    # => true/false, without building the redacted string
```

### Reusable instance (the fast path)

Compile once, scrub millions of times. Compiling ~45 patterns into one automaton is the
expensive part; scanning is cheap.

```ruby
SCRUBBER = Scrubber.new(
  detectors:   Scrubber::DEFAULTS + Scrubber::INDIA,
  custom:      { employee_id: /\bEMP-\d{6}\b/ },
  replacement: :hash                                  # deterministic tokens — logs stay correlatable
)

SCRUBBER.scrub("refund to nik@example.com")           # => "refund to [EMAIL:1efaf05b]"
SCRUBBER.scrub("refund to nik@example.com")           # => same token — grep still works
```

Instances are frozen and hold no per-call state, so one instance is safe to share across every
thread in the process. The module-level `Scrubber.scrub` memoizes one engine per distinct
configuration, so it's fine too — the explicit instance just makes the lifetime obvious.

### Replacement strategies

| strategy | `nik@example.com` | `4111 1111 1111 1111` | `AKIA…EXAMPLE` |
|---|---|---|---|
| `:label` (default) | `[EMAIL]` | `[CREDIT_CARD]` | `[AWS_KEY]` |
| `:mask` | `n**@e******.com` | `**** **** **** 1111` | `********************` |
| `:hash` | `[EMAIL:1efaf05b]` | `[CREDIT_CARD:6a7e0e79]` | `[AWS_KEY:1a5d44a2]` |
| `:remove` | *(deleted)* | *(deleted)* | *(deleted)* |

`:mask` keeps the last four characters of *identifiers* so a human can still recognise the
record, and reveals nothing at all for *secrets* — the last four characters of an API key are
a leak, not a convenience.

`:hash` is `sha256(salt + value)[0, 8]`. Same input, same token, across processes and days, so
logs stay correlatable without holding the value. Pass `hash_salt:` to scope tokens per tenant
or per environment.

### Rails logs — one line

```ruby
# config/initializers/scrubber.rb
Rails.logger.formatter = Scrubber::LogFormatter.new(Rails.logger.formatter)
```

Wrapping the *formatter* rather than the logger catches everything: your own
`Rails.logger.info`, Active Record's SQL echo, Rack's request lines, and the exception messages
your error middleware logs on the way out.

### Rack middleware

```ruby
use Scrubber::Middleware
```

The middleware is deliberately **non-destructive**. It does not rewrite `QUERY_STRING`,
`rack.input`, or `params` — redacting the request your application is about to act on would
break every login form in the world, because the app needs the real password to check it.
What leaks is not the request, it's the *record* of the request.

So it publishes redacted copies for you to record, and cleans exceptions on the way out:

```ruby
env["scrubber.query_string"]  # "user=nik&password=[PASSWORD_PAIR]"
env["scrubber.params"]        # { "user" => "nik", "password" => "[PASSWORD_PAIR]" }
env["scrubber.instance"]      # the engine, for anything else you want to log
```

Any exception raised downstream is re-raised with a redacted message (same class, same
backtrace), so an error tracker that has never heard of this gem still gets a clean payload.
Turn that off with `use Scrubber::Middleware, scrub_exceptions: false`.

### Before your LLM calls

Stop shipping raw customer PII to third-party AI APIs:

```ruby
guard = Scrubber::LLMGuard.new           # defaults to :hash

chat.ask(guard.call(user_message))
```

`LLMGuard` is a plain callable that preserves the shape of what you give it — a String, a
message Array, or a message Hash — so it drops into RubyLLM, langchainrb, ruby-openai,
anthropic-sdk-ruby, or a hand-rolled `Net::HTTP` call the same way:

```ruby
messages = [
  { role: "system", content: "You are a support agent." },
  { role: "user",   content: "my email is nik@example.com and my card is 4111 1111 1111 1111" }
]

client.chat(messages: guard.call(messages))
# => user content becomes "my email is [EMAIL:1efaf05b] and my card is [CREDIT_CARD:6a7e0e79]"
```

Deterministic `:hash` tokens mean the model can still refer to "the same email" across a
conversation without ever seeing it. `guard.findings(messages)` returns what *would* be
redacted, if you want a "we blocked N leaks today" metric or a test that fails when a prompt
builder regresses.

> **On RubyLLM:** as of August 2026 RubyLLM has no public middleware or interceptor hook, so
> this gem ships the wrapper pattern above rather than a plugin. Wrapping the argument at the
> call site is one line and doesn't depend on RubyLLM internals staying put.

### Big files

```ruby
Scrubber.scrub_file("production.log", "production.scrubbed.log")
```

Streams in 1MB chunks with an 8KB carry window, cutting at line boundaries so a match spanning
a chunk boundary is never sliced in half (multi-line PEM blocks get an extra guard). Releases
the GVL for inputs over 64KB, so your Puma threads keep serving.

## Detectors

| Default | Opt-in (India pack) |
|---|---|
| `email`, `phone`, `credit_card` (Luhn), `ssn`, `iban` (mod-97), `ip`, `ipv6`, `mac`, `jwt`, `aws_key`, `api_key`, `private_key`, `password_pair`, `url_credentials` | `phone_in`, `aadhaar` (Verhoeff), `pan`, `upi` |

```ruby
Scrubber.new(detectors: Scrubber::DEFAULTS + Scrubber::INDIA)
Scrubber.new(detectors: %i[email credit_card])   # narrow it down for hot paths
Scrubber::ALL                                    # everything
```

`:api_key` covers 19 provider-specific formats (GitHub, GitLab, Slack, Stripe, OpenAI,
Anthropic, Google, SendGrid, Twilio, npm, PyPI, Shopify, Square, Mailgun, DigitalOcean,
Telegram, AWS secret keys). All of them are structurally unambiguous vendor formats — there is
no entropy heuristic, because those false-positive on git SHAs and UUIDs.

Add your own with `custom: { name: /regexp/ }`. Ruby patterns are translated to Rust regex
syntax; unsupported constructs (backreferences, lookaround, atomic groups, possessive
quantifiers) raise `Scrubber::UnsupportedPatternError` at construction time, naming the
construct. You will never get silent partial coverage.

```ruby
Scrubber.new(custom: { dupe: /(\w)\1/ })
# => Scrubber::UnsupportedPatternError: custom detector "dupe" uses \1, which this engine
#    cannot compile: backreferences require backtracking.
```

### Overlapping matches

When two detectors cover the same span, the more specific one wins: `password=ghp_…` reports
`[API_KEY]`, not `[PASSWORD_PAIR]`. Redaction is always the same either way; only the label
differs. Scrubbing already-scrubbed text is a no-op, so nested middleware won't corrupt lines.

## Benchmarks

<!-- BENCHMARK:START -->
<!-- generated by `rake benchmark`; do not edit by hand -->

| implementation | throughput | relative |
|---|---|---|
| scrubber_rb (Rust core) | **50.4 MB/s** | 1.0x |
| pure-Ruby reference (identical detectors) | 1.3 MB/s | 38.2x slower |

100MB synthetic log corpus (seed 42), all 14 default detectors, single thread, ruby 3.3.0 on arm64-darwin24.
Best of 2 passes. Reproduce with `rake benchmark`.
<!-- BENCHMARK:END -->

Per-line latency, which is what matters when this sits in your logger:

| implementation | one log line | relative |
|---|---|---|
| scrubber_rb | **1.24 µs** | 1.0x |
| pure-Ruby reference | 102.98 µs | 83x slower |

A Rust scan costs about a microsecond per log line, which is why it is safe to put on the
write path of every `Rails.logger` call.

**Methodology**, because a benchmark you can't audit is marketing:

- The baseline in `benchmark/pure_ruby_reference.rb` implements the **identical detector set**
  — same patterns, same Luhn/Verhoeff/mod-97 checksums, same context validators, same
  capture-group behaviour. It is written as good Ruby, not a strawman: one combined `Regexp`,
  one `gsub` pass, no per-detector loop.
- `spec/benchmark_reference_spec.rb` asserts the two implementations **redact identical spans**
  on every fixture and on a slice of the corpus. If someone tightens a Rust detector and
  forgets the reference, the suite fails before anyone reads this table.
- The corpus is seeded synthetic production-shaped logs (`benchmark/corpus/generate.rb`), ~12%
  of lines carrying something redactable. Raising that rate would flatter the Rust engine,
  since pure Ruby is fastest on lines with no matches.
- Throughput is the best of N single-threaded full passes. CI enforces a 5x regression floor
  (`rake benchmark:gate`) rather than restating the headline number, because shared runners
  are noisy.

The difference is architectural, not micro-optimisation. Ruby's Onigmo is a backtracking
engine with no `RegexSet` and no Aho-Corasick prefilter, so every rule in the alternation is
live on every byte. The Rust core runs one Aho-Corasick pass over the literal anchors
(`AKIA`, `-----BEGIN`, `ghp_`, `password`) to eliminate roughly two thirds of the rules before
any regex runs, then one `RegexSet` pass for the rest.

### vs logstop

[`logstop`](https://github.com/ankane/logstop) solves a narrower problem — filtering log lines,
in pure Ruby, with no native extension to build — and has been doing it well since 2019. So the
comparison below restricts `scrubber_rb` to logstop's exact detector set first; running fourteen
detectors it never claimed to have and calling the result a win would prove nothing.

<!-- generated by `rake benchmark:logstop`; do not edit by hand -->

| detector scope | scrubber_rb | logstop | ratio |
|---|---|---|---|
| logstop defaults (`url_password`, `email`, `credit_card`, `phone`, `ssn`) | **153.6 MB/s** | 9.1 MB/s | 16.9x |
| + `ip` and `mac` | **112.9 MB/s** | 8.7 MB/s | 13.0x |

100MB synthetic log corpus, single thread, ruby 3.3.0 on arm64-darwin24, logstop 0.4.1, best of
3 passes.

The speed is the less interesting half. Where they differ on *what* to redact:

| input | scrubber_rb (logstop's scope) | scrubber_rb (all detectors) | logstop |
|---|---|---|---|
| Amex, valid Luhn, 15 digits | redacted | redacted | — |
| Visa, valid Luhn, 16 digits | redacted | redacted | redacted |
| Visa, valid Luhn, 19 digits | redacted | redacted | — |
| 16 digits, fails Luhn | — | — | redacted |
| percent-encoded email | — | — | redacted |
| JWT, AWS key, GitHub token, `password=`, private key, IBAN, IPv6 | — | redacted | — |
| Aadhaar, valid Verhoeff | — | redacted | — |

Read that in both directions. logstop's card regex is `\b[3456]\d{15}\b` — sixteen digits, no
checksum — so it redacts numbers that fail Luhn and misses the 15-digit Amex and 19-digit Visa
lengths entirely. But it also matches percent-encoded values (`%40`, `%2B`, `%3A`) inline, which
`scrubber_rb` does not; see the limitation below.

If log filtering is all you need and you'd rather not build a native extension, logstop is a
perfectly good answer. Reproduce this table with `rake benchmark:logstop`.

## Security

- **ReDoS.** Rust's `regex` crate is a finite-automata engine with no backtracking, so match
  time is linear in input length regardless of the pattern. Attacker-controlled log content
  cannot pin a CPU. Custom Ruby patterns are checked at construction and rejected if they
  require backtracking, so you can't reintroduce the problem through the back door.
- **Panics.** Every FFI entry point is wrapped in `catch_unwind`. A bug in the Rust core
  becomes a `Scrubber::InternalError`, never a process abort.
- **Invalid UTF-8.** Scanning steps over invalid byte sequences and passes them through
  unchanged, so a corrupt log line is scrubbed where it can be and never raises.
- **No network, no persistence, no telemetry.** It's a pure function library.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## What this gem does NOT do

Deterministic patterns can't catch free-form PII — **names, home addresses, medical notes**.
That's NER-model territory. We'd rather be honest about this than give you false confidence.

**Percent-encoded values.** `Scrubber.scrub("e=nik%40example.com")` does not see an email —
detectors run on the literal bytes, and `%40` is not `@`. Decode before scrubbing.
`Scrubber::Middleware` does exactly that for query strings, which is why it reports
`env["scrubber.params"]` rather than scrubbing `QUERY_STRING` in place. If you feed raw encoded
data to `Scrubber.scrub` yourself, `CGI.unescape` it first.

If your threat model includes free-text PII, layer a model-based pass behind this gem's fast
structural pass: [`top_secret`](https://github.com/thoughtbot/top_secret) and its
[`ruby_llm-top_secret`](https://github.com/thoughtbot/ruby_llm-top_secret) integration cover
that ground in Ruby, and Microsoft Presidio does in Python. Structural first (fast, exact),
model second (slow, fuzzy) is the right order.

## Compatibility

Ruby 3.1–3.4 · Linux (x86_64, aarch64; glibc & musl) · macOS (Intel, Apple Silicon) ·
Windows best-effort. CI runs the full matrix plus a weekly ruby-head canary.

## Contributing

```bash
git clone https://github.com/TheSoloHacker47/scrubber-rb && cd scrubber-rb
bin/setup                  # bundle install + rake compile
bundle exec rake           # compile + spec
bundle exec rake ci        # everything CI runs, in CI's order
```

New detector proposals are welcome — include public test vectors and a false-positive analysis
in the PR. See [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/RELEASING.md](docs/RELEASING.md)
for how a release is cut.

## License

[MIT](LICENSE).
