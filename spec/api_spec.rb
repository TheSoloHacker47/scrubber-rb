# frozen_string_literal: true

require "spec_helper"

RSpec.describe Scrubber do
  describe ".new" do
    it "returns a frozen instance" do
      expect(described_class.new).to be_a(Scrubber::Instance).and be_frozen
    end

    it "normalises detector names given as strings" do
      expect(described_class.new(detectors: %w[email ip]).detectors).to eq(%i[email ip])
    end

    it "de-duplicates the detector list" do
      expect(described_class.new(detectors: %i[email email ip]).detectors).to eq(%i[email ip])
    end

    it "rejects a non-Regexp custom detector with a useful message" do
      expect { described_class.new(custom: { thing: "not a regexp" }) }
        .to raise_error(Scrubber::ConfigurationError, /must be a Regexp/)
    end

    it "reports how many rules it compiled" do
      expect(described_class.new(detectors: [:email]).rule_count).to eq(1)
      expect(described_class.new(detectors: [:api_key]).rule_count).to be > 10
    end
  end

  describe ".engine memoization" do
    it "reuses one compiled engine per configuration" do
      expect(described_class.engine).to equal(described_class.engine)
    end

    it "keeps different configurations apart" do
      expect(described_class.engine(replacement: :mask))
        .not_to equal(described_class.engine(replacement: :hash))
    end

    it "treats an equivalent custom Regexp as the same configuration" do
      a = described_class.engine(custom: { t: /\bTKT-\d{6}\b/ })
      b = described_class.engine(custom: { t: /\bTKT-\d{6}\b/ })

      expect(a).to equal(b)
    end

    it "is safe to build concurrently" do
      engines = 16.times.map { Thread.new { described_class.engine(replacement: :mask) } }
                  .map(&:value)

      expect(engines.uniq.size).to eq(1)
    end
  end

  describe ".detect" do
    let(:text) { "mail nik@example.com card #{valid_cards[:visa]}" }

    it "reports the type of each match" do
      expect(described_class.detect(text).map(&:type)).to eq(%i[email credit_card])
    end

    it "reports spans that slice the original string" do
      described_class.detect(text).each do |match|
        expect(text[match.to_range]).not_to be_empty
      end
    end

    it "reports an already-masked preview, never the raw value" do
      preview = described_class.detect(text).first.preview

      expect(preview).to eq("n**@e******.com")
      expect(preview).not_to include("nik@example.com")
    end

    it "returns an empty array for clean text" do
      expect(described_class.detect("nothing here")).to eq([])
    end
  end

  describe ".match?" do
    it "answers without building the redacted string" do
      expect(described_class.match?("nik@example.com")).to be(true)
      expect(described_class.match?("nothing here")).to be(false)
    end
  end

  describe ".scrub!" do
    it "redacts in place and returns the same object" do
      text = +"mail nik@example.com"
      result = described_class.scrub!(text)

      expect(result).to equal(text)
      expect(text).to eq("mail [EMAIL]")
    end

    it "leaves clean strings untouched" do
      text = +"nothing here"
      expect(described_class.scrub!(text)).to equal(text)
    end
  end

  describe "input handling" do
    it "accepts anything with #to_str" do
      stringish = Class.new do
        def to_str = "mail nik@example.com"
      end.new

      expect(described_class.scrub(stringish)).to eq("mail [EMAIL]")
    end

    it "refuses input that is not string-like" do
      expect { described_class.scrub(42) }.to raise_error(TypeError, /String/)
    end

    it "handles an empty string" do
      expect(described_class.scrub("")).to eq("")
      expect(described_class.detect("")).to eq([])
    end
  end

  describe Scrubber::Match do
    subject(:match) { Scrubber.detect("mail nik@example.com").first }

    it "exposes the span as a Range" do
      expect(match.to_range).to eq(5...20)
    end

    it "knows its own length" do
      expect(match.length).to eq(15)
    end

    it "inspects without leaking the value" do
      expect(match.inspect).to include("email").and include("5...20")
      expect(match.inspect).not_to include("nik@example.com")
    end
  end

  describe "constants" do
    it "keeps the region packs out of the defaults" do
      expect(Scrubber::DEFAULTS).not_to include(*Scrubber::INDIA)
    end

    it "sources them from the Rust registry, so there is one list" do
      expect(Scrubber::DEFAULTS).to eq(Scrubber::Native.default_detectors.map(&:to_sym))
    end

    it "freezes them" do
      expect(Scrubber::DEFAULTS).to be_frozen
      expect(Scrubber::INDIA).to be_frozen
      expect(Scrubber::ALL).to be_frozen
    end
  end
end
