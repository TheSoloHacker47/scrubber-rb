# frozen_string_literal: true

require "spec_helper"

# The numbered scenarios from the design brief. If one of these breaks, the gem
# is broken regardless of what the rest of the suite says.
RSpec.describe "behaviour contract" do
  describe "S1: text with no matches" do
    it "returns an equal string with the same encoding" do
      text = "nothing sensitive here at all"
      result = Scrubber.scrub(text)

      expect(result).to eq(text)
      expect(result.encoding).to eq(text.encoding)
    end

    it "returns a distinct object so callers can mutate it" do
      text = +"nothing sensitive here"
      result = Scrubber.scrub(text)

      expect(result).not_to be_frozen
      expect(result.object_id).not_to eq(text.object_id)
    end

    it "leaves the input untouched" do
      text = +"nothing sensitive here"
      Scrubber.scrub(text)
      expect(text).to eq("nothing sensitive here")
    end
  end

  describe "S2: overlapping matches" do
    it "prefers the more specific rule when spans collide" do
      result = Scrubber.scrub("psql postgres://admin:hunter2@mail.example.com/prod")

      expect(result).not_to include("hunter2")
      expect(result).to include("[URL_CREDENTIALS]")
    end

    it "never emits nested or double redactions" do
      result = Scrubber.scrub("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij")

      expect(result.scan("[").size).to eq(result.scan("]").size)
      expect(result).not_to match(/\[[A-Z_]*\[/)
    end

    it "returns non-overlapping, ascending spans from detect" do
      text = "card #{valid_cards[:visa_spaced]} mail nik@example.com ip 10.0.0.1"
      matches = Scrubber.detect(text)

      matches.each_cons(2) do |a, b|
        expect(a.end).to be <= b.begin
      end
    end
  end

  describe "S3: a 16-digit number that fails Luhn" do
    it "is not redacted as a credit card" do
      invalid_cards.each do |number|
        expect(Scrubber.scrub("order #{number} shipped")).to include(number)
      end
    end

    it "still redacts numbers that do pass Luhn" do
      valid_cards.each_value do |number|
        expect(Scrubber.scrub("order #{number} shipped")).to include("[CREDIT_CARD]")
      end
    end
  end

  describe "S4: Aadhaar with separators" do
    it "redacts only when Verhoeff passes" do
      expect(Scrubber.scrub("aadhaar #{valid_aadhaar}", detectors: Scrubber::INDIA))
        .to include("[AADHAAR]")
    end

    it "leaves a same-shaped number with a bad check digit alone" do
      number = invalid_aadhaar
      expect(Scrubber.scrub("aadhaar #{number}", detectors: Scrubber::INDIA))
        .to include(number)
    end

    it "handles dashed and unspaced forms" do
      compact = valid_aadhaar(spaced: false)
      dashed = compact.scan(/\d{4}/).join("-")

      [compact, dashed].each do |form|
        expect(Scrubber.scrub("id #{form}", detectors: Scrubber::INDIA))
          .to include("[AADHAAR]")
      end
    end
  end

  describe "S5: invalid UTF-8 bytes in a log line" do
    let(:line) { (+"user \xFF\xFE logged in from nik@example.com").force_encoding("UTF-8") }

    it "does not raise" do
      expect { Scrubber.scrub(line) }.not_to raise_error
    end

    it "scrubs the valid regions" do
      expect(Scrubber.scrub(line)).to include("[EMAIL]")
    end

    it "preserves the invalid bytes verbatim" do
      expect(Scrubber.scrub(line).bytes).to include(0xFF, 0xFE)
    end

    it "keeps the declared encoding" do
      expect(Scrubber.scrub(line).encoding).to eq(Encoding::UTF_8)
    end

    it "handles a binary string end to end" do
      binary = (+"\x00\x01 nik@example.com \xC3\x28").force_encoding("BINARY")
      result = Scrubber.scrub(binary)

      expect(result.encoding).to eq(Encoding::BINARY)
      expect(result).to include("[EMAIL]")
    end
  end

  describe "S6: :hash mode" do
    it "produces an identical token for the same value" do
      result = Scrubber.scrub("from nik@example.com to nik@example.com", replacement: :hash)
      tokens = result.scan(/\[EMAIL:[0-9a-f]{8}\]/)

      expect(tokens.size).to eq(2)
      expect(tokens.uniq.size).to eq(1)
    end

    it "produces different tokens for different values" do
      result = Scrubber.scrub("a@example.com and b@example.com", replacement: :hash)
      expect(result.scan(/\[EMAIL:[0-9a-f]{8}\]/).uniq.size).to eq(2)
    end

    it "produces a different token under a different salt" do
      plain = Scrubber.scrub("nik@example.com", replacement: :hash)
      salted = Scrubber.scrub("nik@example.com", replacement: :hash, hash_salt: "pepper")

      expect(salted).not_to eq(plain)
      expect(salted).to match(/\A\[EMAIL:[0-9a-f]{8}\]\z/)
    end

    it "is stable across separate engine instances" do
      one = Scrubber.new(replacement: :hash).scrub("nik@example.com")
      two = Scrubber.new(replacement: :hash).scrub("nik@example.com")

      expect(one).to eq(two)
    end
  end

  describe "S7: a custom Regexp with a backreference" do
    it "raises UnsupportedPatternError at construction time" do
      expect { Scrubber.new(custom: { dupe: /(\w)\1/ }) }
        .to raise_error(Scrubber::UnsupportedPatternError)
    end

    it "names the offending construct and the detector" do
      Scrubber.new(custom: { dupe: /(\w)\1/ })
    rescue Scrubber::UnsupportedPatternError => e
      expect(e.message).to include('\1')
      expect(e.message).to include("dupe")
    end

    it "rejects lookbehind and lookahead by name" do
      {
        "(?<=" => /(?<=x)\d+/,
        "(?=" => /\d+(?=x)/
      }.each do |construct, regexp|
        expect { Scrubber.new(custom: { c: regexp }) }
          .to raise_error(Scrubber::UnsupportedPatternError, /#{Regexp.escape(construct)}/)
      end
    end

    it "accepts an ordinary custom pattern" do
      scrubber = Scrubber.new(custom: { ticket_id: /\bTKT-\d{6}\b/ })
      expect(scrubber.scrub("see TKT-004521")).to eq("see [TICKET_ID]")
    end
  end

  describe "S9: a multi-line private key block" do
    it "redacts the whole block as one unit" do
      text = "config:\n#{private_key}done"
      result = Scrubber.scrub(text)

      expect(result).to include("[PRIVATE_KEY]")
      expect(result).not_to include("MIIEpAIBAAKCAQEA")
      expect(result).to include("done")
    end

    it "handles OPENSSH and PGP block headers" do
      %w[OPENSSH EC DSA].each do |kind|
        text = "-----BEGIN #{kind} PRIVATE KEY-----\nbody\n-----END #{kind} PRIVATE KEY-----"
        expect(Scrubber.scrub(text)).to eq("[PRIVATE_KEY]")
      end
    end
  end

  describe "S10: frozen string input" do
    it "works and returns a new, unfrozen string" do
      frozen = "mail nik@example.com"
      result = Scrubber.scrub(frozen)

      expect(result).to eq("mail [EMAIL]")
      expect(result).not_to be_frozen
    end

    it "works when there is nothing to redact" do
      expect(Scrubber.scrub("clean line")).to eq("clean line")
    end

    it "raises FrozenError from the bang variant, like every other bang method" do
      expect { Scrubber.scrub!("mail nik@example.com") }.to raise_error(FrozenError)
    end
  end

  describe "S11: character offsets on multibyte text" do
    let(:text) { "🎉 नमस्ते nik@example.com ✅" }

    it "indexes the Ruby string, not the byte buffer" do
      match = Scrubber.detect(text).first

      expect(text[match.begin...match.end]).to eq("nik@example.com")
    end

    it "disagrees with byte offsets, which is the whole point" do
      match = Scrubber.detect(text).first
      byte_start = text.b.index("nik@")

      expect(byte_start).to be > match.begin
      expect(match.begin).to eq(text.index("nik@"))
    end

    it "handles several matches in one multibyte string" do
      multi = "📧 nik@example.com 🇮🇳 ops@example.org"
      Scrubber.detect(multi).each do |match|
        expect(multi[match.to_range]).to include("@example.")
      end
    end
  end

  describe "S12: a shared instance under concurrency" do
    it "produces identical results from many threads with no crashes" do
      scrubber = Scrubber.new(replacement: :hash)
      input = "user nik@example.com card #{valid_cards[:visa]} ip 10.1.2.3"
      expected = scrubber.scrub(input)

      results = 32.times.map do
        Thread.new { 100.times.map { scrubber.scrub(input) } }
      end.flat_map(&:value)

      expect(results.uniq).to eq([expected])
    end

    it "survives concurrent scans over the GVL-release threshold" do
      scrubber = Scrubber.new
      big = "line with nik@example.com\n" * 8_000
      expect(big.bytesize).to be > 64 * 1024

      threads = 8.times.map { Thread.new { scrubber.scrub(big).length } }
      expect(threads.map(&:value).uniq.size).to eq(1)
    end

    it "is frozen, so there is no shared mutable state to race on" do
      expect(Scrubber.new).to be_frozen
    end
  end
end
