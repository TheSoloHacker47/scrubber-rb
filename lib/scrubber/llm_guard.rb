# frozen_string_literal: true

module Scrubber
  # Redact prompts on their way to a third-party model API.
  #
  #   guard = Scrubber::LLMGuard.new(replacement: :hash)
  #   chat.ask(guard.call(user_message))
  #
  # `:hash` is the interesting default here. With `[EMAIL:9f86d081]` tokens the
  # model can still reason about "the same customer" across a conversation, and
  # your logs of that conversation stay correlatable, without the value ever
  # crossing the network.
  #
  # It accepts the shapes prompts actually come in:
  #
  #   guard.call("my email is nik@example.com")
  #   guard.call([{ role: "user", content: "..." }])
  #   guard.call({ role: "user", content: "..." })
  #
  # There is no framework hook here on purpose. `LLMGuard` is a plain callable,
  # so it drops into RubyLLM, langchainrb, ruby-openai, anthropic-sdk-ruby, or a
  # hand-rolled `Net::HTTP` call the same way. See the README for the RubyLLM
  # wrapper pattern.
  class LLMGuard
    # Message hash keys whose values are prompt text.
    CONTENT_KEYS = %w[content text prompt input].freeze

    attr_reader :scrubber

    def initialize(scrubber: nil, replacement: :hash, **options)
      @scrubber = scrubber || Scrubber.new(replacement: replacement, **options)
    end

    # Redact `input`, preserving its shape.
    def call(input)
      case input
      when String then @scrubber.scrub(input)
      when Array  then input.map { |item| call(item) }
      when Hash   then scrub_hash(input)
      when Symbol, Numeric, NilClass, TrueClass, FalseClass then input
      else
        input.respond_to?(:to_str) ? @scrubber.scrub(input.to_str) : input
      end
    end
    alias scrub call

    # Usable directly as a block: `messages.map(&guard)`.
    def to_proc
      method(:call).to_proc
    end

    # What would have been redacted. Handy for a "we blocked N leaks today"
    # metric, or for failing a test when a prompt builder regresses.
    def findings(input)
      case input
      when String then @scrubber.detect(input)
      when Array  then input.flat_map { |item| findings(item) }
      when Hash   then content_values(input).flat_map { |v| findings(v) }
      else []
      end
    end

    private

    def scrub_hash(hash)
      hash.each_with_object(hash.class.new) do |(key, value), out|
        out[key] = content_key?(key) || value.is_a?(Array) || value.is_a?(Hash) ? call(value) : value
      end
    end

    def content_values(hash)
      hash.filter_map { |key, value| value if content_key?(key) }
    end

    def content_key?(key)
      CONTENT_KEYS.include?(key.to_s)
    end
  end
end
