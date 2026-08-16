# frozen_string_literal: true

require "spec_helper"
require "logger"
require "stringio"

RSpec.describe Scrubber::LogFormatter do
  let(:io) { StringIO.new }
  let(:logger) do
    Logger.new(io).tap { |l| l.formatter = described_class.new(l.formatter) }
  end

  it "redacts what the wrapped formatter produced" do
    logger.info("charge for nik@example.com")

    expect(io.string).to include("[EMAIL]")
    expect(io.string).not_to include("nik@example.com")
  end

  it "keeps the wrapped formatter's layout" do
    logger.warn("plain message")

    expect(io.string).to match(/\AW, \[.*\]\s+WARN -- : plain message\n\z/)
  end

  it "works when the logger has no formatter of its own" do
    bare = Logger.new(io)
    bare.formatter = described_class.new
    bare.info("mail nik@example.com")

    expect(io.string).to include("[EMAIL]")
  end

  it "accepts a prebuilt scrubber" do
    formatter = described_class.new(nil, scrubber: Scrubber.new(replacement: :hash))
    output = formatter.call("INFO", Time.now, nil, "nik@example.com")

    expect(output).to match(/\[EMAIL:[0-9a-f]{8}\]/)
  end

  it "forwards options to Scrubber.new" do
    formatter = described_class.new(nil, detectors: [:email])
    output = formatter.call("INFO", Time.now, nil, "card #{Vectors::VALID_CARDS[:visa]}")

    expect(output).to include(Vectors::VALID_CARDS[:visa])
  end

  it "redacts exception messages that a logger formats" do
    logger.error(RuntimeError.new("cannot reach postgres://app:hunter2@db/prod"))

    expect(io.string).not_to include("hunter2")
  end

  it "passes non-String formatter output through unchanged" do
    formatter = described_class.new(->(*) { :not_a_string })
    expect(formatter.call("INFO", Time.now, nil, "x")).to eq(:not_a_string)
  end
end
