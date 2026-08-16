# frozen_string_literal: true

require "spec_helper"
require_relative "../benchmark/pure_ruby_reference"

# The "10x faster than pure Ruby" claim is only meaningful if the pure-Ruby
# baseline actually does the same job. These specs are what stops the benchmark
# from quietly becoming a lie: if someone tightens a Rust detector and forgets
# the reference, this fails long before anyone reads the README.
# The Rust engine resolves overlapping matches by detector priority; Ruby's
# leftmost-first alternation resolves them by position. That can change which
# label is printed, never which bytes are removed, so equivalence is asserted
# with labels normalised away.
REDACTION_LABEL = /\[[A-Z][A-Z0-9_]*(?::[0-9a-f]+)?\]/

RSpec.describe PureRubyReference do
  def normalise(text) = text.gsub(REDACTION_LABEL, "[X]")

  def agree_on(text)
    expect(normalise(described_class.scrub(text)))
      .to eq(normalise(Scrubber.scrub(text))), "disagreement on #{text.inspect}"
  end

  it "redacts the same spans on every fixture" do
    fixture_paths.each do |path|
      agree_on(fixture(File.basename(path)))
    end
  end

  it "agrees on the headline example" do
    agree_on("contact nik@example.com, card #{valid_cards[:visa_spaced]}, key #{aws_key}")
  end

  it "agrees on each detector's positive cases" do
    [
      "mail nik.nelson+tag@sub.example.co.uk",
      "call +14155552671 or 415-555-2671",
      *valid_cards.values.map { |c| "card #{c}" },
      "ssn 123-45-6789",
      "acct #{iban}",
      "from 10.0.0.1 to 192.168.100.7",
      "peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 and fe80::1",
      "nic 00:1a:2b:3c:4d:5e",
      "bearer #{jwt}",
      "key #{aws_key}",
      "gh ghp_#{"a" * 36}",
      private_key,
      "login password=hunter2 next=/home",
      "psql postgres://app:hunter2@db.internal/prod"
    ].each { |text| agree_on(text) }
  end

  it "agrees on each detector's negative cases" do
    [
      *invalid_cards.map { |c| "order #{c}" },
      "ssn 666-45-6789",
      "acct GB82 WEST 1234 5698 7654 31",
      "ip 999.1.1.1",
      "at 12:34:56 done",
      "PG::ConnectionBad raised in Foo::Bar::Baz",
      "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
      "Ruby 3.3.0 / Rails 7.2.1 / puma 6.4.2"
    ].each { |text| agree_on(text) }
  end

  it "agrees that already-redacted text is left alone" do
    once = Scrubber.scrub("login password=hunter2 mail nik@example.com")
    agree_on(once)
  end

  it "agrees on a slice of the benchmark corpus" do
    corpus = File.expand_path("../benchmark/corpus/production.log", __dir__)
    skip "run `rake corpus` first" unless File.exist?(corpus)

    sample = File.binread(corpus, 512 * 1024).force_encoding("UTF-8")
    agree_on(sample[0...sample.rindex("\n")])
  end

  it "is genuinely doing the work, not returning the input" do
    expect(described_class.scrub("mail nik@example.com")).to eq("mail [EMAIL]")
  end

  it "runs the same checksums" do
    expect(described_class.scrub("order #{invalid_cards.first}"))
      .to include(invalid_cards.first)
    expect(described_class.scrub("order #{valid_cards[:visa]}"))
      .to include("[CREDIT_CARD]")
  end
end
