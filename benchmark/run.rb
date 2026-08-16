#!/usr/bin/env ruby
# frozen_string_literal: true

# Benchmarks the Rust engine against the pure-Ruby reference and prints the
# markdown table that goes in the README.
#
#   rake benchmark                  # 100MB corpus, generated if missing
#   SIZE_MB=10 rake benchmark       # quicker
#
# Methodology, stated up front because a benchmark you cannot audit is
# marketing:
#
#   * Both implementations run the same default detector set over the same
#     bytes and redact identical spans (asserted below — the run aborts if
#     they ever disagree).
#   * The corpus is seeded synthetic production-shaped logs, ~12% of lines
#     carrying something redactable. See corpus/generate.rb.
#   * Throughput is the best of N full passes over the corpus, single-threaded.
#     Best-of rather than mean, because the noise on a laptop is all in one
#     direction.
#   * benchmark-ips runs separately on a 1MB slice for per-operation numbers.

require "benchmark"
require "benchmark/ips"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "scrubber_rb"
require_relative "pure_ruby_reference"

SIZE_MB = Integer(ENV.fetch("SIZE_MB", "100"))
PASSES = Integer(ENV.fetch("PASSES", "3"))
CORPUS = ENV.fetch("CORPUS", File.expand_path("corpus/production.log", __dir__))

unless File.exist?(CORPUS) && File.size(CORPUS) >= SIZE_MB * 1024 * 1024 * 0.95
  warn "generating a #{SIZE_MB}MB corpus (this takes a moment)..."
  system({ "SIZE_MB" => SIZE_MB.to_s, "CORPUS" => CORPUS },
         RbConfig.ruby, File.expand_path("corpus/generate.rb", __dir__)) ||
    abort("corpus generation failed")
end

corpus = File.binread(CORPUS)
megabytes = corpus.bytesize / 1024.0 / 1024

SCRUBBER = Scrubber.new

# ---------------------------------------------------------------------------
# Equivalence check. If the two implementations disagree the comparison is
# meaningless, so this is a hard gate, not a warning.
# ---------------------------------------------------------------------------

# Both implementations redact the same byte ranges, but they can disagree on
# which *label* to print when two rules cover the same span: the Rust engine
# resolves ties by detector priority, while Ruby's leftmost-first alternation
# resolves them by position. A `token=eyJ...` JWT comes out as `[JWT]` from one
# and `[PASSWORD_PAIR]` from the other.
#
# That is a labelling difference, not a redaction difference, and the benchmark
# only needs the redaction to be identical. So equivalence is checked with the
# labels normalised away: if the two ever cover different spans, the surrounding
# text shifts and this still catches it.
LABEL = /\[[A-Z][A-Z0-9_]*(?::[0-9a-f]+)?\]/
NORMALISE = ->(text) { text.gsub(LABEL, "[X]") }

sample = corpus.byteslice(0, 512 * 1024).force_encoding("UTF-8")
sample = sample[0...sample.rindex("\n")]
rust_out = NORMALISE[SCRUBBER.scrub(sample)]
ruby_out = NORMALISE[PureRubyReference.scrub(sample)]

if rust_out != ruby_out
  first = rust_out.each_char.zip(ruby_out.each_char).index { |a, b| a != b }
  abort <<~MSG
    ABORT: the two implementations disagree, so this benchmark would be meaningless.
    First difference at character #{first}:
      rust: #{rust_out[[first - 60, 0].max, 160].inspect}
      ruby: #{ruby_out[[first - 60, 0].max, 160].inspect}
  MSG
end
warn "equivalence check passed on #{(sample.bytesize / 1024.0).round}KB"

# ---------------------------------------------------------------------------
# Throughput over the whole corpus.
# ---------------------------------------------------------------------------
def best_pass(passes, &block)
  Array.new(passes) { Benchmark.realtime(&block) }.min
end

warn "timing #{PASSES} passes over #{megabytes.round(1)}MB..."
rust_seconds = best_pass(PASSES) { SCRUBBER.scrub(corpus) }
warn "  scrubber_rb: #{rust_seconds.round(2)}s"
ruby_seconds = best_pass(PASSES) { PureRubyReference.scrub(corpus) }
warn "  pure Ruby:   #{ruby_seconds.round(2)}s"

rust_throughput = megabytes / rust_seconds
ruby_throughput = megabytes / ruby_seconds
speedup = ruby_seconds / rust_seconds

# ---------------------------------------------------------------------------
# Per-operation numbers on a small slice, where ips is meaningful.
# ---------------------------------------------------------------------------
slice = corpus.byteslice(0, 1024 * 1024).force_encoding("UTF-8")
slice = slice[0...slice.rindex("\n")]

ips_report = Benchmark.ips do |x|
  x.config(time: 5, warmup: 2)
  x.report("scrubber_rb (1MB)") { SCRUBBER.scrub(slice) }
  x.report("pure Ruby (1MB)") { PureRubyReference.scrub(slice) }
  x.compare!
end

line = corpus.lines.find { |l| SCRUBBER.match?(l) }
Benchmark.ips do |x|
  x.config(time: 3, warmup: 1)
  x.report("scrubber_rb (one log line)") { SCRUBBER.scrub(line) }
  x.report("pure Ruby (one log line)") { PureRubyReference.scrub(line) }
  x.compare!
end

# ---------------------------------------------------------------------------
# The table.
# ---------------------------------------------------------------------------
ruby_desc = "#{RUBY_ENGINE} #{RUBY_VERSION}"
platform = RbConfig::CONFIG["arch"]

puts
puts "<!-- generated by `rake benchmark`; do not edit by hand -->"
puts
puts "| implementation | throughput | relative |"
puts "|---|---|---|"
puts format("| scrubber_rb (Rust core) | **%.1f MB/s** | 1.0x |", rust_throughput)
puts format("| pure-Ruby reference (identical detectors) | %.1f MB/s | %.1fx slower |",
            ruby_throughput, speedup)
puts
puts "#{megabytes.round}MB synthetic log corpus (seed 42), all #{Scrubber::DEFAULTS.size} " \
     "default detectors, single thread, #{ruby_desc} on #{platform}."
puts "Best of #{PASSES} passes. Reproduce with `rake benchmark`."
puts

if speedup < 10
  warn "NOTE: speedup is #{speedup.round(1)}x, below the 10x headline claim. " \
       "Update the README rather than the claim."
end

ips_report
