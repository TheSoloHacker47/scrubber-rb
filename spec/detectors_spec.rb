# frozen_string_literal: true

require "spec_helper"

RSpec.describe "detectors" do
  # Redact `text` with exactly one detector enabled, so a passing example can
  # only be the detector under test.
  def only(detector, text)
    Scrubber.scrub(text, detectors: [detector])
  end

  describe ":email" do
    it "catches the shapes that turn up in logs" do
      [
        "nik@example.com",
        "nik.nelson+tag@sub.example.co.uk",
        "n_1%test@example-host.io",
        "UPPER@EXAMPLE.COM"
      ].each do |address|
        expect(only(:email, "to #{address} ok")).to eq("to [EMAIL] ok")
      end
    end

    it "leaves near-misses alone" do
      ["not.an.email", "@example.com", "nik@", "nik@localhost", "a@b"].each do |text|
        expect(only(:email, "x #{text} y")).to include(text)
      end
    end
  end

  describe ":phone" do
    it "catches E.164 and common written formats" do
      ["+14155552671", "+1 415 555 2671", "415-555-2671", "(415) 555-2671",
       "415.555.2671"].each do |number|
        expect(only(:phone, "call #{number} now")).to include("[PHONE]")
      end
    end

    it "does not fire on version numbers or dates" do
      ["2024-01-15", "v1.2.3", "127.0.0.1"].each do |text|
        expect(only(:phone, "x #{text} y")).to include(text)
      end
    end
  end

  describe ":phone_in" do
    it "catches Indian mobile numbers in their usual forms" do
      ["+919876543210", "+91 9876543210", "09876543210", "9876543210"].each do |number|
        expect(only(:phone_in, "sms #{number}")).to include("[PHONE_IN]")
      end
    end

    it "rejects numbers that cannot start an Indian mobile" do
      expect(only(:phone_in, "id 1234567890 x")).to include("1234567890")
    end
  end

  describe ":credit_card" do
    it "accepts published test numbers in every separator style" do
      valid_cards.each_value do |number|
        expect(only(:credit_card, "pan #{number}")).to include("[CREDIT_CARD]")
      end
    end

    it "rejects Luhn failures and out-of-range lengths" do
      (invalid_cards + %w[411111111111 41111111111111111111]).each do |number|
        expect(only(:credit_card, "n #{number} z")).to include(number)
      end
    end
  end

  describe ":ssn" do
    it "catches dashed and spaced forms" do
      ["123-45-6789", "123 45 6789"].each do |ssn|
        expect(only(:ssn, "ssn #{ssn}")).to include("[SSN]")
      end
    end

    it "rejects ranges the SSA never issues" do
      %w[000-45-6789 666-45-6789 900-45-6789 123-00-6789 123-45-0000].each do |ssn|
        expect(only(:ssn, "ssn #{ssn}")).to include(ssn)
      end
    end
  end

  describe ":iban" do
    it "accepts a mod-97-valid IBAN" do
      expect(only(:iban, "acct #{iban}")).to include("[IBAN]")
    end

    it "rejects a bad checksum and an unregistered country" do
      ["GB82 WEST 1234 5698 7654 31", "ZZ82WEST12345698765432"].each do |bad|
        expect(only(:iban, "acct #{bad}")).to include(bad.split.first)
      end
    end
  end

  describe ":ip and :ipv6" do
    it "catches IPv4 addresses" do
      ["10.0.0.1", "192.168.100.7", "255.255.255.255"].each do |ip|
        expect(only(:ip, "from #{ip}")).to eq("from [IP]")
      end
    end

    it "rejects impossible octets" do
      expect(only(:ip, "from 999.1.1.1")).to include("999.1.1.1")
    end

    it "catches IPv6 addresses including compressed forms" do
      ["2001:0db8:85a3:0000:0000:8a2e:0370:7334", "fe80::1", "::1",
       "::ffff:192.168.1.1"].each do |ip|
        expect(only(:ipv6, "peer #{ip}")).to include("[IPV6]")
      end
    end

    it "does not mistake a timestamp for an address" do
      expect(only(:ipv6, "at 12:34:56 done")).to include("12:34:56")
    end
  end

  describe ":mac" do
    it "catches colon, dash and Cisco forms" do
      ["00:1a:2b:3c:4d:5e", "00-1A-2B-3C-4D-5E", "001a.2b3c.4d5e"].each do |mac|
        expect(only(:mac, "nic #{mac}")).to include("[MAC]")
      end
    end
  end

  describe ":jwt" do
    it "catches a three-segment token" do
      expect(only(:jwt, "Authorization: Bearer #{jwt}")).to include("[JWT]")
    end

    it "ignores a base64 blob that is not a JWT" do
      expect(only(:jwt, "data aGVsbG8gd29ybGQ=")).to include("aGVsbG8gd29ybGQ=")
    end
  end

  describe ":aws_key" do
    it "catches access key ids" do
      %w[AKIA ASIA AROA].each do |prefix|
        key = prefix + ("A".."Z").to_a.first(16).join
        expect(only(:aws_key, "key #{key}")).to include("[AWS_KEY]")
      end
    end

    it "catches the documented example key" do
      expect(only(:aws_key, "id #{aws_key}")).to eq("id [AWS_KEY]")
    end
  end

  describe ":api_key" do
    {
      "GitHub PAT" => "ghp_#{"a" * 36}",
      "GitHub fine-grained" => "github_pat_#{"A" * 70}",
      "GitLab PAT" => "glpat-#{"x" * 20}",
      "Slack bot token" => "xoxb-123456789012-#{"a" * 24}",
      "Stripe secret" => Vectors::STRIPE_SECRET_KEY,
      "Anthropic" => "sk-ant-#{"a" * 40}",
      "Google API" => "AIza#{"B" * 35}",
      "SendGrid" => "SG.#{"a" * 22}.#{"b" * 43}",
      "npm" => "npm_#{"c" * 36}",
      "Shopify" => "shpat_#{"0123456789abcdef" * 2}",
      "DigitalOcean" => "dop_v1_#{"0" * 64}"
    }.each do |name, token|
      it "catches a #{name}" do
        expect(only(:api_key, "key=#{token}")).to include("[API_KEY]")
        expect(only(:api_key, "key=#{token}")).not_to include(token)
      end
    end

    it "does not fire on ordinary hex like a git SHA" do
      sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
      expect(only(:api_key, "commit #{sha}")).to include(sha)
    end
  end

  describe ":password_pair" do
    it "redacts the value and keeps the key readable" do
      {
        "password=hunter2" => "password=[PASSWORD_PAIR]",
        "passwd: hunter2" => "passwd: [PASSWORD_PAIR]",
        '{"secret":"hunter2"}' => '{"secret":"[PASSWORD_PAIR]"}',
        "api_key = hunter2" => "api_key = [PASSWORD_PAIR]"
      }.each do |input, expected|
        expect(only(:password_pair, input)).to eq(expected)
      end
    end

    it "stops at the query-string separator" do
      expect(only(:password_pair, "/login?password=hunter2&next=/home"))
        .to eq("/login?password=[PASSWORD_PAIR]&next=/home")
    end
  end

  describe ":url_credentials" do
    it "redacts only the password" do
      expect(only(:url_credentials, "postgres://app:hunter2@db.internal/prod"))
        .to eq("postgres://app:[URL_CREDENTIALS]@db.internal/prod")
    end

    it "leaves credential-free URLs alone" do
      expect(only(:url_credentials, "https://example.com/path"))
        .to eq("https://example.com/path")
    end
  end

  describe ":pan" do
    it "checks the entity character" do
      expect(only(:pan, "pan ABCPE1234F")).to eq("pan [PAN]")
      expect(only(:pan, "code ABCXE1234F")).to include("ABCXE1234F")
    end
  end

  describe ":upi" do
    it "catches VPAs on known PSP handles" do
      ["nik@ybl", "9876543210@paytm", "nik.nelson@okaxis"].each do |vpa|
        expect(only(:upi, "pay #{vpa}")).to include("[UPI]")
      end
    end

    it "does not swallow email addresses" do
      expect(only(:upi, "mail nik@upi.example.com")).to include("nik@upi.example.com")
      expect(only(:upi, "mail nik@gmail.com")).to include("nik@gmail.com")
    end
  end

  describe "detector selection" do
    it "leaves India-pack types alone by default" do
      text = "aadhaar #{valid_aadhaar} pan ABCPE1234F"
      expect(Scrubber.scrub(text)).to include("ABCPE1234F")
    end

    it "picks them up when the pack is enabled" do
      text = "aadhaar #{valid_aadhaar} pan ABCPE1234F"
      result = Scrubber.scrub(text, detectors: Scrubber::DEFAULTS + Scrubber::INDIA)

      expect(result).to include("[AADHAAR]", "[PAN]")
    end

    it "exposes every registered key through ALL" do
      expect(Scrubber::ALL).to match_array(Scrubber::DEFAULTS + Scrubber::INDIA)
    end

    it "compiles every detector at once" do
      expect { Scrubber.new(detectors: Scrubber::ALL) }.not_to raise_error
    end
  end
end
