#!/usr/bin/env ruby
# frozen_string_literal: true

# CI performance gate.
#
# The headline claim is 10x on a developer machine. CI runners are noisy shared
# hardware, so the gate is set at 5x: high enough that a real regression trips
# it, low enough that a bad neighbour on the hypervisor does not.
#
#   PERF_FLOOR=5 SIZE_MB=10 ruby benchmark/gate.rb

require "benchmark"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "scrubber_rb"
require_relative "pure_ruby_reference"

FLOOR = Float(ENV.fetch("PERF_FLOOR", "5"))
SIZE_MB = Integer(ENV.fetch("SIZE_MB", "10"))
PASSES = Integer(ENV.fetch("PASSES", "3"))
CORPUS = ENV.fetch("CORPUS", File.expand_path("corpus/gate.log", __dir__))

unless File.exist?(CORPUS)
  system({ "SIZE_MB" => SIZE_MB.to_s, "CORPUS" => CORPUS },
         RbConfig.ruby, File.expand_path("corpus/generate.rb", __dir__)) ||
    abort("corpus generation failed")
end

corpus = File.binread(CORPUS)
megabytes = corpus.bytesize / 1024.0 / 1024
scrubber = Scrubber.new

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

# Same hard equivalence gate as the full benchmark: a faster implementation
# that redacts different things is not faster, it is broken.
sample = corpus.byteslice(0, 256 * 1024).force_encoding("UTF-8")
sample = sample[0...sample.rindex("\n")]
unless NORMALISE[scrubber.scrub(sample)] == NORMALISE[PureRubyReference.scrub(sample)]
  abort "FAIL: the Rust engine and the pure-Ruby reference redact different spans"
end

best = ->(&blk) { Array.new(PASSES) { Benchmark.realtime(&blk) }.min }

rust = best.call { scrubber.scrub(corpus) }
ruby = best.call { PureRubyReference.scrub(corpus) }
speedup = ruby / rust

puts format("corpus:      %.1f MB", megabytes)
puts format("scrubber_rb: %.3fs (%.1f MB/s)", rust, megabytes / rust)
puts format("pure Ruby:   %.3fs (%.1f MB/s)", ruby, megabytes / ruby)
puts format("speedup:     %.2fx (floor %.1fx)", speedup, FLOOR)

abort format("FAIL: %.2fx is below the %.1fx regression floor", speedup, FLOOR) if speedup < FLOOR

puts "PASS"
