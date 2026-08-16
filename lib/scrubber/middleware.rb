# frozen_string_literal: true

module Scrubber
  # Rack middleware that makes a redacted view of the request available to
  # everything downstream, and redacts exception messages on the way out.
  #
  #   use Scrubber::Middleware, detectors: Scrubber::DEFAULTS
  #
  # == What it does not do
  #
  # It does not rewrite `QUERY_STRING`, `rack.input`, or `params`. Redacting the
  # request the application is about to act on would break every login form in
  # the world: the app needs the real password to check it. What leaks is not
  # the request, it is the *record* of the request — the log line, the error
  # tracker payload, the APM trace.
  #
  # So this middleware gives you redacted copies to record:
  #
  #   env["scrubber.query_string"]  # "user=x&password=[PASSWORD_PAIR]"
  #   env["scrubber.params"]        # { "user" => "x", "password" => "[PASSWORD_PAIR]" }
  #   env["scrubber.instance"]      # the engine, for anything else you log
  #
  # and it redacts the message of any exception raised further down the stack
  # before re-raising it, so an error tracker that never heard of this gem still
  # gets a clean payload.
  class Middleware
    QUERY_STRING = "QUERY_STRING"
    ENV_QUERY = "scrubber.query_string"
    ENV_PARAMS = "scrubber.params"
    ENV_INSTANCE = "scrubber.instance"

    attr_reader :scrubber

    # @param app [#call] the next Rack app.
    # @param scrubber [Scrubber::Instance] a prebuilt engine, if you have one.
    # @param scrub_exceptions [Boolean] redact exception messages (default true).
    # @param options [Hash] otherwise, options for {Scrubber.new}.
    def initialize(app, scrubber: nil, scrub_exceptions: true, **options)
      @app = app
      @scrubber = scrubber || Scrubber.new(**options)
      @scrub_exceptions = scrub_exceptions
    end

    def call(env)
      annotate(env)
      @app.call(env)
    rescue StandardError => e
      raise unless @scrub_exceptions

      raise redacted(e)
    end

    private

    def annotate(env)
      env[ENV_INSTANCE] = @scrubber
      query = env[QUERY_STRING]
      return if query.nil? || query.empty?

      # Decode *before* scrubbing. `email=nik%40example.com` does not look like
      # an email address until the `%40` is a `@`, and a redactor that can be
      # defeated by percent-encoding is not a redactor. The decoded key is put
      # back in front of the value before scrubbing, because `:password_pair`
      # needs that context to recognise `hunter2` as a password at all.
      pairs = parse_pairs(query).map { |key, value| [key, scrub_value(key, value)] }

      env[ENV_PARAMS] = pairs.to_h
      # Rebuilt from the decoded pairs, so this is a string for logs to print,
      # not a query string to re-issue a request with.
      env[ENV_QUERY] = pairs.map { |key, value| "#{key}=#{value}" }.join("&")
    end

    # Deliberately not `Rack::Utils.parse_nested_query`: this is a logging aid,
    # it must never raise on a malformed query string, and the gem must stay
    # loadable without Rack.
    def parse_pairs(query)
      query.split("&").filter_map do |pair|
        key, _, value = pair.partition("=")
        next if key.empty?

        [unescape(key), unescape(value)]
      end
    end

    def scrub_value(key, value)
      scrubbed = @scrubber.scrub("#{key}=#{value}")
      prefix = "#{key}="
      scrubbed.start_with?(prefix) ? scrubbed[prefix.length..] : scrubbed.partition("=").last
    end

    def unescape(str)
      decoded = str.tr("+", " ").gsub(/%([0-9a-fA-F]{2})/) { [Regexp.last_match(1)].pack("H2") }
      decoded.force_encoding(Encoding::UTF_8)
      decoded.valid_encoding? ? decoded : decoded.force_encoding(Encoding::BINARY)
    rescue StandardError
      str
    end

    # Rebuild the exception with a redacted message, keeping its class and
    # backtrace so error groupers still group it the same way.
    def redacted(error)
      message = error.message
      return error unless message.is_a?(String)

      clean = @scrubber.scrub(message)
      return error if clean == message

      replacement = rebuild(error, clean)
      return error if replacement.nil?

      replacement.set_backtrace(error.backtrace) if error.backtrace
      replacement
    end

    # Some exception classes have a non-standard `initialize` and cannot be
    # rebuilt from a message. Better the original than a crash in the middleware
    # that was supposed to protect you.
    def rebuild(error, message)
      error.exception(message)
    rescue StandardError
      nil
    end
  end
end
