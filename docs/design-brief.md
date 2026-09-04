# The original design brief

> **Historical document.** This is the brief `scrubber_rb` was built from, written
> before any code existed and preserved unedited. It is published because the design
> work happened here, not in the implementation.
>
> **It is not documentation.** For what the gem does today, including the current
> detector list and public API, read the [README](../README.md) and
> [CHANGELOG](../CHANGELOG.md). Where the two disagree, they are right and this is old.

**License:** MIT. **Stack:** Ruby gem with a Rust native extension (magnus + rb-sys).

---

## 0. Elevator pitch

`scrubber_rb` takes text and returns it with sensitive data redacted — emails, phones, credit
cards, Indian IDs (Aadhaar/PAN/UPI), IPs, JWTs, API keys, private keys — in a single fast pass
through a Rust core. One engine, three use cases:

1. **Log scrubbing** — Rails logger formatter + Rack middleware (incumbent: `logstop`, pure Ruby, log-only).
2. **LLM pre-flight** — redact prompts before they're sent to OpenAI/Anthropic/etc. (RubyLLM integration).
3. **Secret detection** — catch leaked credentials before they hit logs, error trackers, or LLMs.

The pitch is speed + completeness: Rust's `regex`/`aho-corasick` crates scanning multi-pattern
over large text is where a real, benchmarkable 10x+ over pure-Ruby regex lives. The benchmark
chart IS the launch post.

**Read before coding:**
- magnus (Rust↔Ruby bindings): https://github.com/matsadler/magnus
- rb-sys + cross-compilation: https://github.com/oxidize-rb/rb-sys and the
  `oxidize-rb/actions` cross-gem GitHub Action: https://github.com/oxidize-rb/actions
- A shipped example of the exact packaging model (precompiled per-platform Rust gem, built on
  GH Actions): https://github.com/njaremko/osv — copy its release ergonomics, not its code.
- Incumbent to benchmark against: https://github.com/ankane/logstop
- Pattern references: gitleaks default config (secrets), Microsoft Presidio docs (PII taxonomy —
  for naming/organization only; we implement deterministic detectors, not NER).

---

## 1. Naming

**`scrubber_rb`**, namespace `Scrubber`, which is what shipped.

The name had to clear two checks before anything was built: that it was free on
RubyGems, and that the bare `Scrubber` namespace would not collide confusingly with an
existing popular gem. A namespace clash is cheap to avoid up front and expensive to fix
after release, which is why this section came first.

---

## 2. Goals / non-goals

**Goals:**
- G1. Deterministic detectors (regex/checksum-based) with near-zero false negatives on
  structured PII and low false positives (checksums: Luhn for cards, Verhoeff for Aadhaar).
- G2. ≥10x faster than an equivalent pure-Ruby implementation on a 100MB log corpus
  (single-thread, measured with benchmark-ips; the repo ships the benchmark).
- G3. Safe by construction: never panic across the FFI boundary; handle invalid UTF-8 bytes
  gracefully (scrub what's scannable, pass the rest through unchanged).
- G4. Batteries included for Rails: logger formatter, Rack params middleware, and a documented
  RubyLLM integration — each usable in one line.
- G5. Precompiled gems for all mainstream platforms; installing never requires a Rust toolchain.
- G6. v1 scope honesty: deterministic patterns only. Names/addresses (NER territory) are an
  explicit non-goal, stated in the README.

**Non-goals:**
- NG1. No ML/NER models in v1 (no name/address detection).
- NG2. No async/streaming API in v1 (chunked helper is enough; see 3.4).
- NG3. No persistence, no network calls, no telemetry — pure function library.
- NG4. Windows support is best-effort (`x64-mingw-ucrt` build attempted; not a release blocker).

---

## 3. Public API (frozen — do not change without approval)

### 3.1 Core

```ruby
require 'scrubber_rb'

Scrubber.scrub("mail me at nik@example.com")
# => "mail me at [EMAIL]"

Scrubber.scrub(text, detectors: [:email, :phone_in, :aadhaar, :api_key],
                     replacement: :mask)      # :label (default) | :mask | :hash | :remove

Scrubber.detect(text)
# => [Scrubber::Match(type: :email, begin: 11, end: 26, preview: "n***@e***.com"), ...]
# begin/end are CHARACTER offsets into the Ruby string (not bytes) — convert in Rust.

s = Scrubber.new(
  detectors: Scrubber::DEFAULTS + [:aadhaar, :pan, :upi],
  custom:    { ticket_id: /\bTKT-\d{6}\b/ },   # user-supplied Ruby Regexp, compiled to Rust
  replacement: :hash                            # deterministic sha256[0,8] → correlation-safe
)
s.scrub(text)     # reusable, compiled once — this is the fast path; document it
s.scrub!(text)    # in-place-flavored variant returning the same behavior (dup + replace)
s.detect(text)
```

Replacement strategies:
- `:label`  → `[EMAIL]`, `[CREDIT_CARD]`, `[AADHAAR]` …
- `:mask`   → partial: keep first char + domain TLD for emails, last 4 for cards, etc. (define per detector)
- `:hash`   → `[EMAIL:9f86d081]` — sha256 hex prefix of the value; same input → same token, so
  logs remain correlatable without exposing the value. Optional `hash_salt:` kwarg.
- `:remove` → deleted entirely.

Custom `Regexp` handling: translate Ruby regex source to Rust `regex` syntax; on unsupported
constructs (backreferences, lookbehind) raise `Scrubber::UnsupportedPatternError` at
construction time with a clear message — never silently degrade.

### 3.2 Detector set (v1)

| key | method | notes |
|---|---|---|
| `:email` | regex | RFC-lite, not full RFC 5322 |
| `:phone` | regex | E.164 + common intl formats |
| `:phone_in` | regex | Indian mobile (+91/0 prefixed, 10-digit starting 6-9) |
| `:credit_card` | regex + **Luhn** | 13–19 digits, separators allowed; Luhn must pass |
| `:aadhaar` | regex + **Verhoeff** | 12 digits, spaces/dashes allowed; Verhoeff must pass |
| `:pan` | regex | `[A-Z]{5}[0-9]{4}[A-Z]` with 4th-char entity check |
| `:upi` | regex | `handle@psp` against known PSP suffix list (constant, editable) |
| `:ssn` | regex | US SSN incl. invalid-range rejection |
| `:iban` | regex + mod-97 | |
| `:ip` / `:ipv6` | regex + octet validation | |
| `:mac` | regex | |
| `:jwt` | regex | three base64url segments, `eyJ` anchor |
| `:aws_key` | aho-corasick anchor `AKIA`/`ASIA` + regex | |
| `:private_key` | anchor `-----BEGIN` … `-----END` block | multi-line |
| `:api_key` | gitleaks-style generic patterns (curated subset ~15 rules) | keep the list in one Rust file with source comments |
| `:password_pair` | `password=`, `passwd:`, `secret=` key/value in logs & URLs | value only is redacted |
| `:url_credentials` | `scheme://user:pass@host` | pass only is redacted |

`Scrubber::DEFAULTS` = everything except `:phone_in`, `:aadhaar`, `:pan`, `:upi` (region packs
are opt-in via `detectors: Scrubber::DEFAULTS + Scrubber::INDIA`). Export both constants.

### 3.3 Integrations (thin Ruby, no Rust)

```ruby
# Rails logger — config/initializers/scrubber.rb
Rails.logger.formatter = Scrubber::LogFormatter.new(Rails.logger.formatter)

# Rack middleware (scrubs request params before they reach app logging/error trackers)
use Scrubber::Middleware, detectors: Scrubber::DEFAULTS

# RubyLLM pre-flight (document in README; implement as a tiny module)
chat = RubyLLM.chat.with_middleware(Scrubber::LLMGuard.new(replacement: :hash))
```
`LLMGuard`: agent must check RubyLLM's current extension/middleware API at build time and adapt
— if RubyLLM has no middleware hook, ship it as a documented wrapper pattern instead and open
an upstream issue proposing a hook. Do not fork RubyLLM.

### 3.4 Large inputs

`Scrubber.scrub_file(in_path, out_path, **opts)` — streams in 1MB chunks with a carry-over
window (max pattern span 8KB) so matches crossing chunk boundaries aren't missed. Releases the
GVL during Rust scanning for inputs > 64KB (use `rb_sys`/magnus `nogvl` support) so Puma threads
aren't blocked.

### 3.5 Behavior contract (write tests from these)

| # | Scenario | Expected |
|---|----------|----------|
| S1 | text with 0 matches | returned string is the SAME object content, equal encoding; no allocations churn beyond one dup |
| S2 | overlapping matches (email inside URL creds) | longest/most-specific wins; no double-redaction artifacts |
| S3 | 16-digit number failing Luhn | NOT redacted as credit_card |
| S4 | valid Aadhaar with spaces `2341 2341 2341` style | redacted only if Verhoeff passes |
| S5 | invalid UTF-8 bytes embedded in a log line | no exception; valid regions scrubbed; invalid bytes preserved |
| S6 | `:hash` mode, same email twice | identical token both times; different with different `hash_salt:` |
| S7 | custom Regexp with backreference | raises `UnsupportedPatternError` at `Scrubber.new`, message names the construct |
| S8 | 100MB synthetic log corpus | ≥10x faster than the pure-Ruby reference impl in `benchmark/` (CI perf job asserts ≥5x as a regression floor) |
| S9 | multi-line private key block | whole block → `[PRIVATE_KEY]` |
| S10 | frozen string input | works; returns new string |
| S11 | character offsets in `detect` on multibyte text (emoji + Hindi) | offsets index the Ruby string correctly |
| S12 | 10k threads calling a shared `Scrubber` instance | no crashes, no data races (instance is immutable after construction) |

---

## 4. Architecture

### 4.1 Repo layout

```
scrubber_rb/
├── Cargo.toml                       # workspace
├── ext/scrubber_rb/
│   ├── Cargo.toml                   # crate: magnus, rb-sys, regex, aho-corasick, sha2
│   ├── extconf.rb                   # require 'mkmf'; require 'rb_sys/mkmf'; create_rust_makefile
│   └── src/
│       ├── lib.rb.rs → lib.rs       # magnus init: defines Scrubber::Native
│       ├── engine.rs                # compile detector set → single RegexSet + AC automaton; scan pass
│       ├── detectors/mod.rs         # one file per detector family; pattern + validate() (Luhn/Verhoeff/mod97)
│       ├── replace.rs               # label/mask/hash/remove strategies
│       └── offsets.rs               # byte↔char offset mapping for S11
├── lib/
│   ├── scrubber_rb.rb               # loads precompiled .so/.bundle by platform, falls back to compile
│   └── scrubber/
│       ├── version.rb  defaults.rb  match.rb
│       ├── log_formatter.rb  middleware.rb  llm_guard.rb
├── spec/                            # Ruby-side specs (S1–S12 + integration files)
├── benchmark/
│   ├── pure_ruby_reference.rb       # honest same-detector pure-Ruby impl (this is the 10x baseline)
│   ├── vs_logstop.rb                # scoped to what logstop covers; be fair, note scope difference
│   └── corpus/generate.rb           # synthetic 100MB log generator (seeded, reproducible)
├── .github/workflows/{ci.yml,cross-gem.yml}
├── scrubber_rb.gemspec  Gemfile  Rakefile
└── README.md CHANGELOG.md LICENSE CONTRIBUTING.md CODE_OF_CONDUCT.md
```

### 4.2 Engine design (the perf-critical part)

- **One pass, two stages.** Stage 1: `aho-corasick` automaton over literal anchors
  (`AKIA`, `-----BEGIN`, `eyJ`, `password=`, `@`, digit-runs are NOT anchored — regex handles
  those) to cheaply localize candidate windows for expensive rules. Stage 2: a single
  `regex::RegexSet` + per-pattern `Regex` for capture extraction, run only where needed.
  Then run checksum validators on candidates. Collect all matches, resolve overlaps
  (longest match, then detector priority order), apply replacements in one output build
  (no repeated `gsub` — build the output string with a rope/Vec<u8> walk).
- Rust `regex` is linear-time (no backtracking) — say this in docs; it's also a security
  feature vs ReDoS on attacker-controlled log content. Mention in README security section.
- Instance = compiled engine, immutable, `Send + Sync`; wrap in magnus `TypedData`. All
  per-call state lives on the stack (S12).
- GVL release for inputs > 64KB (see 3.4). Copy the input into Rust before releasing the GVL
  (never touch Ruby memory without it).
- Panic hygiene: every entry point wrapped so a Rust panic becomes `Scrubber::InternalError`,
  never a process abort (`std::panic::catch_unwind` at the boundary; magnus helps here).

### 4.3 Packaging & builds

- Scaffold with `bundle gem scrubber_rb --ext=rust` (Bundler generates the magnus/rb-sys
  skeleton), then reshape to the layout above.
- `rake compile` (rake-compiler) for local dev; `rake native gem` for platform gems.
- `cross-gem.yml`: on tag `v*`, use `oxidize-rb/actions/cross-gem` to build
  `x86_64-linux`, `x86_64-linux-musl`, `aarch64-linux`, `aarch64-linux-musl`, `arm64-darwin`,
  `x86_64-darwin`, and attempt `x64-mingw-ucrt` (allowed to fail, NG4). Also publish the
  source ("ruby" platform) gem for exotic platforms. Publish via RubyGems Trusted Publishing.
- `required_ruby_version '>= 3.1'`. Runtime dep: `rb_sys` only for the source gem path.

---

## 5. Testing

### 5.1 Rust (`cargo test`, run in CI before Ruby specs)

- Per-detector table tests: valid/invalid/boundary cases — especially Luhn, Verhoeff, mod-97
  vectors (include known-good public test numbers, e.g. 4111111111111111 for Luhn).
- Overlap resolution unit tests (S2), offset mapping tests with multibyte strings (S11).
- Fuzz-lite: proptest with random byte strings — invariant: never panics, output length sane (S5, G3).

### 5.2 Ruby (RSpec)

- S1–S12 as specs; integration specs feeding real-world-shaped fixtures (an nginx access log,
  a Rails production log excerpt, a JSON API payload, a `.env` file).
- Formatter/middleware specs with a fake Rails logger and Rack::MockRequest.
- Encoding matrix: UTF-8, ASCII-8BIT with invalid bytes, frozen strings.

### 5.3 Performance CI

- `benchmark/run.rb` prints a markdown table (tool: benchmark-ips, corpus seeded).
- CI perf job (ubuntu only) asserts ≥5x vs `pure_ruby_reference.rb` as a regression floor
  (S8 target is 10x locally; CI machines are noisy, hence the lower gate).

### 5.4 CI matrix (`ci.yml`)

- OS: ubuntu-latest, macos-latest. Ruby: 3.1–3.4. Steps: setup-ruby (+ rustup stable),
  `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `rake compile`,
  `rake spec`, rubocop. Weekly scheduled run against ruby-head as an early-warning canary.

---

## 6. GitHub repo setup

Same conventions as the bundler-overrule repo: MIT, Contributor Covenant, CONTRIBUTING with
`bin/setup` (installs rustup if missing) → `rake compile spec`, issue templates (bug template
asks for `Scrubber::VERSION`, platform gem or source build, and a minimal input string —
REMINDING the reporter to redact it first, which is a nice on-brand touch), PR template,
branch protection, squash merges.

Description: "Fast PII & secret redaction for Ruby — Rust-cored. Scrub logs, prompts, and
payloads before they leak." Topics: `ruby`, `rust`, `magnus`, `pii`, `redaction`, `gdpr`,
`dpdp`, `security`, `logging`, `llm`, `rails`.

## 7. Definition of done (v0.1.0)

- S1–S12 green on the full matrix; cargo clippy/fmt clean; coverage ≥ 90% on `lib/`.
- Precompiled gems for all six primary platforms install and pass a smoke script on a machine
  with NO Rust toolchain (`gem install scrubber_rb && ruby -e 'require "scrubber_rb"; puts Scrubber.scrub("a@b.com")'`).
- Benchmark table generated from a real run committed into README.
- README quickstart works verbatim in a fresh Rails app.

## 8. Launch checklist (owner)

- Launch post: "I made PII redaction 10x faster by moving it to Rust" — include the honest
  benchmark methodology and the NER non-goal. Cross-post dev.to + own blog.
- PR to the RubyLLM ecosystem page adding the LLMGuard integration; submit to Ruby Weekly;
  r/ruby; r/rails; Show HN; X thread with the benchmark chart.
- Respectful `vs logstop` section: different scope (logstop = log filtering, this = general
  engine); credit it, don't dunk.
- India angle content: "Aadhaar/PAN/UPI-aware log scrubbing for Indian SaaS (DPDP Act)" —
  nobody else has this; separate short post targeting Indian dev communities.
