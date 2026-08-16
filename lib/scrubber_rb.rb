# frozen_string_literal: true

require_relative "scrubber/version"

# Precompiled platform gems ship the extension under a Ruby ABI directory
# (lib/scrubber_rb/3.3/scrubber_rb.so); a source build puts it one level up.
begin
  RUBY_VERSION =~ /(\d+\.\d+)/
  require_relative "scrubber_rb/#{Regexp.last_match(1)}/scrubber_rb"
rescue LoadError
  require_relative "scrubber_rb/scrubber_rb"
end

require_relative "scrubber/match"
require_relative "scrubber/instance"
require_relative "scrubber/log_formatter"
require_relative "scrubber/middleware"
require_relative "scrubber/llm_guard"

# Fast PII and secret redaction, with the scanning done in Rust.
#
#   Scrubber.scrub("contact nik@example.com")  # => "contact [EMAIL]"
#
# The module-level methods are the convenient path and memoize one compiled
# engine per distinct configuration. For hot loops, build a {Scrubber::Instance}
# yourself with {Scrubber.new} and keep it around.
module Scrubber
  # Detectors enabled unless you say otherwise. Sourced from the Rust registry
  # so there is exactly one copy of this list in the project.
  DEFAULTS = Native.default_detectors.map(&:to_sym).freeze

  # Opt-in India pack, for DPDP Act workloads:
  #
  #   Scrubber.new(detectors: Scrubber::DEFAULTS + Scrubber::INDIA)
  INDIA = Native.india_detectors.map(&:to_sym).freeze

  # Every detector this build knows about.
  ALL = Native.all_detectors.map(&:to_sym).freeze

  class << self
    # Build a reusable, frozen scrubber. See {Scrubber::Instance}.
    def new(detectors: DEFAULTS, custom: {}, replacement: :label, hash_salt: nil)
      Instance.new(
        detectors: detectors, custom: custom,
        replacement: replacement, hash_salt: hash_salt
      )
    end

    # Redact `text` using a memoized engine for these options.
    def scrub(text, **options)
      engine(**options).scrub(text)
    end

    # Redact `text` in place.
    def scrub!(text, **options)
      engine(**options).scrub!(text)
    end

    # Locate matches without replacing them. Returns {Scrubber::Match} structs.
    def detect(text, **options)
      engine(**options).detect(text)
    end

    # True if anything would be redacted.
    def match?(text, **options)
      engine(**options).match?(text)
    end

    # Stream a file through the engine. Returns bytes written.
    def scrub_file(input_path, output_path, **options)
      chunk_size = options.delete(:chunk_size) || Instance::CHUNK_SIZE
      engine(**options).scrub_file(input_path, output_path, chunk_size: chunk_size)
    end

    # The memoized {Scrubber::Instance} for a set of options. Exposed because
    # asking for it explicitly beats accidentally rebuilding one per request.
    def engine(detectors: DEFAULTS, custom: {}, replacement: :label, hash_salt: nil)
      key = Instance.cache_key(
        detectors: detectors, custom: custom,
        replacement: replacement, hash_salt: hash_salt
      )
      # Double-checked: reads are lock-free on the happy path, and building the
      # same engine twice under a race is harmless (they are identical and
      # immutable), so the mutex only prevents wasted work.
      cache[key] || cache_mutex.synchronize do
        cache[key] ||= new(
          detectors: detectors, custom: custom,
          replacement: replacement, hash_salt: hash_salt
        )
      end
    end

    # Drop memoized engines. Only useful in tests.
    def reset!
      cache_mutex.synchronize { cache.clear }
      nil
    end

    private

    def cache
      @cache ||= {}
    end

    def cache_mutex
      @cache_mutex ||= Mutex.new
    end
  end
end
