# frozen_string_literal: true

require "spec_helper"

# Unit tests prove each detector works on a string built to please it. These
# run the whole default set over text shaped like the real thing, and assert
# the two properties that matter: nothing sensitive survives, and everything
# else does.
RSpec.describe "real-world fixtures" do
  shared_examples "a redacted fixture" do |name, leaks:, keeps:|
    let(:raw) { fixture(name) }
    let(:scrubbed) { Scrubber.scrub(raw, detectors: Scrubber::ALL) }

    it "removes every sensitive value" do
      leaks.each do |secret|
        expect(scrubbed).not_to include(secret), "#{name} still leaks #{secret.inspect}"
      end
    end

    it "keeps the surrounding structure intact" do
      keeps.each do |kept|
        expect(scrubbed).to include(kept), "#{name} lost #{kept.inspect}"
      end
    end

    it "does not change the line count" do
      expect(scrubbed.lines.size).to eq(raw.lines.size)
    end

    it "is idempotent" do
      expect(Scrubber.scrub(scrubbed, detectors: Scrubber::ALL)).to eq(scrubbed)
    end
  end

  describe "an nginx access log" do
    it_behaves_like "a redacted fixture", "nginx_access.log",
                    leaks: [
                      "nik@example.com",
                      "hunter2",
                      "203.0.113.42",
                      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    ],
                    keeps: ["GET /users", "HTTP/1.1", "kube-probe/1.29", "Mozilla/5.0"]
  end

  describe "a Rails production log" do
    it_behaves_like "a redacted fixture", "rails_production.log",
                    leaks: [
                      "nik@example.com",
                      "4111 1111 1111 1111",
                      "+14155552671",
                      "hunter2"
                    ],
                    keeps: [
                      "Started POST",
                      "PG::ConnectionBad",
                      "Completed 500 Internal Server Error",
                      "INSERT INTO"
                    ]
  end

  describe "a JSON API payload" do
    it_behaves_like "a redacted fixture", "payload.json",
                    leaks: [
                      "nik@example.com",
                      "nik@ybl",
                      "ABCPE1234F",
                      "4012-8888-8888-1881",
                      "GB82 WEST 1234 5698 7654 32",
                      Vectors::STRIPE_SECRET_KEY
                    ],
                    keeps: ["\"customer\"", "\"payment\"", "\"meta\"", "trace_id"]

    it "is still parseable JSON afterwards" do
      require "json"
      scrubbed = Scrubber.scrub(fixture("payload.json"), detectors: Scrubber::ALL)

      expect { JSON.parse(scrubbed) }.not_to raise_error
    end
  end

  describe "a .env file" do
    it_behaves_like "a redacted fixture", "dotenv",
                    leaks: [
                      "hunter2",
                      "AKIAIOSFODNN7EXAMPLE",
                      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                      "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                      Vectors::STRIPE_SECRET_KEY
                    ],
                    keeps: ["DATABASE_URL=", "AWS_ACCESS_KEY_ID=", "LOG_LEVEL=debug"]
  end

  describe "false positives on ordinary application logs" do
    let(:benign) do
      <<~LOG
        Completed 200 OK in 43ms (Views: 12.1ms | ActiveRecord: 8.3ms)
        Migrating to AddIndexToOrders (20260816091233)
        Cache hit rate 0.9871 over 1048576 keys
        Deployed sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b
        Ruby 3.3.0 / Rails 7.2.1 / puma 6.4.2 (4 threads)
        GET /assets/application-4f3c2b1a.js 200
      LOG
    end

    it "leaves them completely alone" do
      expect(Scrubber.scrub(benign, detectors: Scrubber::ALL)).to eq(benign)
    end
  end
end
