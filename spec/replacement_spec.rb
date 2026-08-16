# frozen_string_literal: true

require "spec_helper"

RSpec.describe "replacement strategies" do
  describe ":label (default)" do
    it "names the detector in upper case" do
      expect(Scrubber.scrub("nik@example.com")).to eq("[EMAIL]")
      expect(Scrubber.scrub(valid_cards[:visa])).to eq("[CREDIT_CARD]")
    end

    it "uses the custom detector's own name" do
      scrubber = Scrubber.new(custom: { employee_id: /\bEMP-\d{6}\b/ })
      expect(scrubber.scrub("EMP-004521")).to eq("[EMPLOYEE_ID]")
    end
  end

  describe ":mask" do
    it "keeps an email recognisable without revealing it" do
      expect(Scrubber.scrub("nik@example.com", replacement: :mask))
        .to eq("n**@e******.com")
    end

    it "keeps the last four digits of a card and its grouping" do
      expect(Scrubber.scrub(valid_cards[:visa_spaced], replacement: :mask))
        .to eq("**** **** **** 1111")
      expect(Scrubber.scrub(valid_cards[:visa], replacement: :mask))
        .to eq("************1111")
    end

    it "reveals nothing at all for secrets" do
      masked = Scrubber.scrub("key #{aws_key}", replacement: :mask)

      expect(masked).to match(/\Akey \*+\z/)
      expect(masked).not_to include("EXAMPLE")
    end
  end

  describe ":hash" do
    it "emits a stable eight-hex-character token" do
      expect(Scrubber.scrub("nik@example.com", replacement: :hash))
        .to match(/\A\[EMAIL:[0-9a-f]{8}\]\z/)
    end

    it "keeps logs correlatable across lines" do
      one = Scrubber.scrub("login nik@example.com", replacement: :hash)
      two = Scrubber.scrub("logout nik@example.com", replacement: :hash)

      expect(one[/\[EMAIL:[0-9a-f]{8}\]/]).to eq(two[/\[EMAIL:[0-9a-f]{8}\]/])
    end

    it "does not leak across salts" do
      a = Scrubber.scrub("nik@example.com", replacement: :hash, hash_salt: "tenant-a")
      b = Scrubber.scrub("nik@example.com", replacement: :hash, hash_salt: "tenant-b")

      expect(a).not_to eq(b)
    end
  end

  describe ":remove" do
    it "deletes the value entirely" do
      expect(Scrubber.scrub("mail nik@example.com now", replacement: :remove))
        .to eq("mail  now")
    end

    it "never grows the output" do
      text = "a@b.com " * 100
      expect(Scrubber.scrub(text, replacement: :remove).bytesize).to be < text.bytesize
    end
  end

  describe "validation" do
    it "rejects an unknown strategy by name" do
      expect { Scrubber.new(replacement: :redact) }
        .to raise_error(Scrubber::ConfigurationError, /redact/)
    end

    it "lists the strategies it does accept" do
      expect { Scrubber.new(replacement: :redact) }
        .to raise_error(Scrubber::ConfigurationError, /label.*mask.*hash.*remove/)
    end

    it "accepts strategy names as strings" do
      expect(Scrubber.new(replacement: "mask").replacement).to eq(:mask)
    end
  end
end
