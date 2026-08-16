# frozen_string_literal: true

module Scrubber
  # Wraps an existing Logger formatter and redacts whatever it produces.
  #
  #   # config/initializers/scrubber.rb
  #   Rails.logger.formatter = Scrubber::LogFormatter.new(Rails.logger.formatter)
  #
  # Wrapping the formatter rather than the logger means it catches everything:
  # your own `Rails.logger.info`, Active Record's SQL echo, Rack's request
  # lines, and the exception messages your error middleware logs on the way out.
  #
  # It runs on the log write path, so it is worth knowing what it costs: one
  # Rust scan per line, which on typical log lines is a few microseconds. If
  # your app is log-bound, narrow `detectors:` to what you actually care about.
  class LogFormatter
    attr_reader :scrubber

    # @param formatter [#call] the formatter to wrap. Defaults to
    #   `Logger::Formatter`, which is what a bare `Logger` uses.
    # @param scrubber [Scrubber::Instance] a prebuilt engine, if you have one.
    # @param options [Hash] otherwise, options for {Scrubber.new}.
    def initialize(formatter = nil, scrubber: nil, **options)
      @formatter = formatter || self.class.default_formatter
      @scrubber = scrubber || Scrubber.new(**options)
    end

    def call(severity, time, progname, msg)
      formatted = @formatter.call(severity, time, progname, msg)
      return formatted unless formatted.is_a?(String)

      @scrubber.scrub(formatted)
    end

    def self.default_formatter
      require "logger"
      ::Logger::Formatter.new
    end
  end
end
