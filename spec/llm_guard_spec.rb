# frozen_string_literal: true

require "spec_helper"

RSpec.describe Scrubber::LLMGuard do
  subject(:guard) { described_class.new }

  it "defaults to :hash so the model can still correlate" do
    expect(guard.call("mail nik@example.com")).to match(/\[EMAIL:[0-9a-f]{8}\]/)
  end

  it "gives the same token to the same value across calls" do
    first = guard.call("from nik@example.com")
    second = guard.call("reply to nik@example.com")

    expect(first[/\[EMAIL:[0-9a-f]{8}\]/]).to eq(second[/\[EMAIL:[0-9a-f]{8}\]/])
  end

  it "redacts a chat message array in place of its shape" do
    messages = [
      { role: "system", content: "You are helpful." },
      { role: "user", content: "charge card #{Vectors::VALID_CARDS[:visa]}" }
    ]
    result = guard.call(messages)

    expect(result.first[:role]).to eq("system")
    expect(result.last[:content]).to include("[CREDIT_CARD:")
    expect(result.last[:content]).not_to include(Vectors::VALID_CARDS[:visa])
  end

  it "leaves non-content keys alone" do
    result = guard.call({ "role" => "user", "name" => "nik@example.com", "content" => "hi" })

    expect(result["name"]).to eq("nik@example.com")
    expect(result["content"]).to eq("hi")
  end

  it "recurses into nested content blocks" do
    input = { "content" => [{ "type" => "text", "text" => "mail nik@example.com" }] }
    result = guard.call(input)

    expect(result["content"].first["text"]).to include("[EMAIL:")
  end

  it "passes non-text values through unchanged" do
    expect(guard.call(nil)).to be_nil
    expect(guard.call(42)).to eq(42)
    expect(guard.call(:sym)).to eq(:sym)
  end

  it "does not mutate the caller's messages" do
    messages = [{ role: "user", content: "mail nik@example.com" }]
    guard.call(messages)

    expect(messages.first[:content]).to eq("mail nik@example.com")
  end

  it "is usable as a block" do
    expect(["nik@example.com"].map(&guard).first).to include("[EMAIL:")
  end

  it "reports what it would redact, for metrics" do
    findings = guard.findings([{ "content" => "mail nik@example.com and 10.0.0.1" }])

    expect(findings.map(&:type)).to contain_exactly(:email, :ip)
  end

  it "accepts a different replacement strategy" do
    labelled = described_class.new(replacement: :label)
    expect(labelled.call("nik@example.com")).to eq("[EMAIL]")
  end
end
