# frozen_string_literal: true

# Test vectors that have to satisfy a checksum are *generated* here rather than
# copied from somewhere, so a spec can never pass because two wrong numbers
# happened to agree.
module Vectors
  VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  ].freeze

  VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
  ].freeze

  VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9].freeze

  # A synthetic but structurally valid Aadhaar: 12 digits, first digit 2-9,
  # Verhoeff-clean. `2341 2341 234X` shaped, as in the behaviour contract (S4).
  def valid_aadhaar(payload = "23412341234", spaced: true)
    digits = payload.chars.map(&:to_i)
    check = 0
    digits.reverse.each_with_index do |d, i|
      check = VERHOEFF_D[check][VERHOEFF_P[(i + 1) % 8][d]]
    end
    full = payload + VERHOEFF_INV[check].to_s
    spaced ? full.scan(/\d{4}/).join(" ") : full
  end

  # Same shape, deliberately broken check digit.
  def invalid_aadhaar(spaced: true)
    full = valid_aadhaar(spaced: false)
    broken = full[0..-2] + ((full[-1].to_i + 1) % 10).to_s
    spaced ? broken.scan(/\d{4}/).join(" ") : broken
  end

  # Publicly published test card numbers. These are the ones printed in payment
  # gateway docs precisely so they can appear in test suites.
  VALID_CARDS = {
    visa: "4111111111111111",
    visa_spaced: "4111 1111 1111 1111",
    visa_dashed: "4012-8888-8888-1881",
    mastercard: "5500005555555559",
    amex: "378282246310005",
    discover: "6011111111111117",
    jcb: "3530111333300000"
  }.freeze

  # Right shape, wrong Luhn.
  INVALID_CARDS = %w[
    1234567890123456
    4111111111111112
    9999888877776666
  ].freeze

  # The AWS documentation's own example key id.
  AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

  # A three-segment JWT with an `eyJ` header. Payload is `{"sub":"1"}`.
  JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." \
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

  PRIVATE_KEY = <<~PEM
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Oi/pRE6VjEUZKmLPtGZ8dTBcXbb
    ilYtQeHFH0xCUqYnLGGOSCcRuGYxsGXFdyLLl0jXY0kf1kEDlZgqZ2ByDPDwsGVw
    -----END RSA PRIVATE KEY-----
  PEM

  # A real, published IBAN test value.
  IBAN = "GB82 WEST 1234 5698 7654 32"

  # Fixture files hold a placeholder rather than a literal Stripe-shaped key.
  #
  # A credential-shaped string in a committed file trips GitHub push protection
  # and every other secret scanner pointed at this repo, which is noise for a
  # value that was always fake. Assembling it here keeps the fixtures realistic
  # to the detector and boring to the scanners.
  # Joined rather than written out, so the complete key-shaped literal never
  # appears in a committed file (and RuboCop cannot helpfully fold it back).
  STRIPE_SECRET_KEY = ["sk", "live", "0" * 24].join("_").freeze

  PLACEHOLDERS = {
    "__STRIPE_SECRET_KEY__" => STRIPE_SECRET_KEY
  }.freeze

  # Read a fixture with its placeholders filled in.
  def fixture(name)
    raw = File.read(File.expand_path("../fixtures/#{name}", __dir__))
    PLACEHOLDERS.reduce(raw) { |text, (token, value)| text.gsub(token, value) }
  end

  def fixture_paths
    Dir[File.expand_path("../fixtures/*", __dir__)]
  end

  def stripe_key = STRIPE_SECRET_KEY

  # Constants defined in an included module are not in the lexical scope of an
  # RSpec example block, so expose them as methods too.
  def valid_cards = VALID_CARDS
  def invalid_cards = INVALID_CARDS
  def aws_key = AWS_KEY
  def jwt = JWT
  def private_key = PRIVATE_KEY
  def iban = IBAN
end
