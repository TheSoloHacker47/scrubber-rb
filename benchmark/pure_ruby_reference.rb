# frozen_string_literal: true

require "set"
require "ipaddr"

# An honest pure-Ruby implementation of the same default detector set.
#
# This is the baseline the "10x" claim is measured against, so it matters that
# it is *good* Ruby, not a strawman:
#
#   * one combined Regexp, not one `gsub` per detector (N passes would be an
#     easy win and an unfair one);
#   * a single `gsub` over the input, building the output once;
#   * the same checksums (Luhn, Verhoeff, mod-97) and the same context
#     validators, so it makes the same decisions on the same input;
#   * the same capture-group behaviour, so `password=x` redacts only `x`.
#
# What it cannot copy is the architecture: Ruby's Onigmo is a backtracking
# engine with no `RegexSet` and no Aho-Corasick prefilter, so every rule in the
# alternation is live on every byte. That difference is the benchmark.
module PureRubyReference
  Rule = Struct.new(:kind, :source, :validator, :captures, keyword_init: true)

  # The same three checksums the Rust core runs, in plain Ruby.
  module Checksums
    module_function

    def luhn(digits)
      return false if digits.length < 12

      sum = 0
      digits.reverse.each_with_index do |d, i|
        v = d
        if i.odd?
          v *= 2
          v -= 9 if v > 9
        end
        sum += v
      end
      (sum % 10).zero?
    end

    VERHOEFF_D = [
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
      [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
      [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
      [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ].freeze

    VERHOEFF_P = [
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
      [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
      [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ].freeze

    def verhoeff(digits)
      c = 0
      digits.reverse.each_with_index { |d, i| c = VERHOEFF_D[c][VERHOEFF_P[i % 8][d]] }
      c.zero?
    end

    def mod97(compact)
      return false if compact.length < 15 || compact.length > 34

      rotated = compact[4..] + compact[0, 4]
      rem = 0
      rotated.each_char do |ch|
        val = ch =~ /\d/ ? ch.to_i : (ch.ord - 65 + 10)
        rem = val >= 10 ? ((rem * 100) + val) % 97 : ((rem * 10) + val) % 97
      end
      rem == 1
    end
  end

  IBAN_COUNTRIES = %w[
    AD AE AL AT AZ BA BE BG BH BI BR BY CH CR CY CZ DE DJ DK DO EE EG ES FI FK
    FO FR GB GE GI GL GR GT HN HR HU IE IL IQ IS IT JO KW KZ LB LC LI LT LU LV
    LY MC MD ME MK MN MR MT MU NI NL NO OM PK PL PS PT QA RO RS RU SA SC SD SE
    SI SK SM SO ST SV TL TN TR UA VA VG XK YE
  ].to_set

  DIGITS = ->(s) { s.scan(/\d/).map(&:to_i) }

  PASSWORD_KEYS = "password|passwd|pwd|secret|api[_\\-]?key|apikey|" \
                  "access[_\\-]?token|auth[_\\-]?token|token"

  # Same rules, same order, same priorities as ext/scrubber_rb/src/detectors.
  RULES = [
    Rule.new(kind: "private_key", captures: false,
             source: "-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----.*?" \
                     "-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----"),
    Rule.new(kind: "aws_key", captures: false,
             source: '\bA(?:KIA|SIA|IDA|ROA|GPA|NPA|NVA|PKA|IPA)[0-9A-Z]{16}\b'),
    Rule.new(kind: "api_key", captures: false,
             source: '\bgh[pousr]_[A-Za-z0-9]{36,255}\b'),
    Rule.new(kind: "api_key", captures: false,
             source: '\bgithub_pat_[A-Za-z0-9_]{60,120}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bglpat-[A-Za-z0-9_\-]{20,64}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bxox[baprse]-[A-Za-z0-9\-]{10,72}\b'),
    Rule.new(kind: "api_key", captures: false,
             source: 'https://hooks\.slack\.com/services/[A-Za-z0-9_/\-]{20,}'),
    Rule.new(kind: "api_key", captures: false,
             source: '\b[srp]k_(?:live|test)_[A-Za-z0-9]{16,247}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bsk-ant-[A-Za-z0-9_\-]{20,120}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,160}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bAIza[0-9A-Za-z_\-]{35}\b'),
    Rule.new(kind: "api_key", captures: false,
             source: '\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\b(?:SK|AC)[0-9a-fA-F]{32}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bnpm_[A-Za-z0-9]{36}\b'),
    Rule.new(kind: "api_key", captures: false,
             source: '\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}'),
    Rule.new(kind: "api_key", captures: false, source: '\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bsq0(?:atp|csp|idp)-[A-Za-z0-9_\-]{22,64}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bkey-[0-9a-f]{32}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\bdop_v1_[a-f0-9]{64}\b'),
    Rule.new(kind: "api_key", captures: false, source: '\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b'),
    Rule.new(kind: "api_key", captures: true,
             source: '(?i:aws[_\-]?(?:secret[_\-]?)?access[_\-]?key["\']?\s*[:=]\s*["\']?' \
                     "(?<value>[A-Za-z0-9/+=]{40}))"),
    Rule.new(kind: "jwt", captures: false,
             source: '\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*'),
    Rule.new(kind: "url_credentials", captures: true,
             source: '[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@]+:(?<value>[^\s/@]+)@'),
    Rule.new(kind: "password_pair", captures: true,
             source: "(?i:(?:#{PASSWORD_KEYS})[\"']?\\s*[:=]\\s*\"(?<value>[^\"\\n]{1,256})\")",
             validator: ->(v) { !redaction_token?(v) }),
    Rule.new(kind: "password_pair", captures: true,
             source: "(?i:(?:#{PASSWORD_KEYS})[\"']?\\s*[:=]\\s*'(?<value>[^'\\n]{1,256})')",
             validator: ->(v) { !redaction_token?(v) }),
    Rule.new(kind: "password_pair", captures: true,
             source: "(?i:(?:#{PASSWORD_KEYS})[\"']?\\s*[:=]\\s*(?<value>[^\\s,;&\"'}\\]]{1,256}))",
             validator: ->(v) { !redaction_token?(v) }),
    Rule.new(kind: "credit_card", captures: false, source: '\b\d(?:[ \-]?\d){12,18}\b',
             validator: lambda { |v|
               d = DIGITS[v]
               (13..19).cover?(d.length) && Checksums.luhn(d)
             }),
    Rule.new(kind: "iban", captures: false, source: '\b[A-Z]{2}\d{2}(?:[ \-]?[A-Z0-9]){11,30}\b',
             validator: lambda { |v|
               compact = v.gsub(/[^A-Za-z0-9]/, "").upcase
               compact.length >= 15 && IBAN_COUNTRIES.include?(compact[0, 2]) &&
                 Checksums.mod97(compact)
             }),
    Rule.new(kind: "ssn", captures: false, source: '\b\d{3}-\d{2}-\d{4}\b',
             validator: ->(v) { valid_ssn?(DIGITS[v]) }),
    Rule.new(kind: "ssn", captures: false, source: '\b\d{3} \d{2} \d{4}\b',
             validator: ->(v) { valid_ssn?(DIGITS[v]) }),
    Rule.new(kind: "email", captures: false,
             source: '(?<![A-Za-z0-9@])[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?\.[A-Za-z]{2,24}\b',
             validator: ->(v) { valid_email?(v) }),
    Rule.new(kind: "mac", captures: false, source: '\b[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}\b'),
    Rule.new(kind: "mac", captures: false, source: '\b[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}\b'),
    Rule.new(kind: "ipv6", captures: false,
             source: "(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}" \
                     '(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f]{0,4})(?![0-9A-Za-z:])',
             validator: ->(v) { valid_ipv6?(v) }),
    Rule.new(kind: "ip", captures: false,
             source: '(?<![.\-])\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b(?!\.)',
             validator: ->(v) { v.split(".").all? { |o| o.to_i <= 255 } }),
    Rule.new(kind: "phone", captures: false,
             source: '\+[1-9]\d{0,2}[ .\-]?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b'),
    Rule.new(kind: "phone", captures: false, source: '\+[1-9]\d{7,14}\b'),
    Rule.new(kind: "phone", captures: false,
             source: '(?<![A-Za-z0-9])\b\d{3}[ .\-]\d{3}[ .\-]\d{4}\b'),
    Rule.new(kind: "phone", captures: false, source: '\(\d{3}\)[ .\-]?\d{3}[ .\-]?\d{4}\b')
  ].freeze

  def self.redaction_token?(value)
    return false unless value.start_with?("[")

    body = value.delete_prefix("[").delete_suffix("]")
    label, _, digest = body.partition(":")
    return false if label.empty? || !label.match?(/\A[A-Z0-9_]+\z/)

    digest.empty? ? !body.include?(":") : digest.match?(/\A[0-9a-f]+\z/)
  end

  def self.valid_ssn?(digits)
    return false unless digits.length == 9

    area = digits[0, 3].join.to_i
    area.positive? && area != 666 && area < 900 &&
      digits[3, 2].join.to_i.positive? && digits[5, 4].join.to_i.positive?
  end

  def self.valid_email?(value)
    local, _, domain = value.rpartition("@")
    !local.empty? && local.length <= 64 && !local.start_with?(".") && !local.end_with?(".") &&
      !domain.include?("..") && !domain.start_with?(".", "-")
  end

  def self.valid_ipv6?(value)
    IPAddr.new(value).ipv6?
  rescue StandardError
    false
  end

  # One alternation, one pass. Group names are positional (`r0`, `r1`, ...)
  # because Onigmo will not let two branches share a capture name.
  COMBINED = Regexp.new(
    RULES.each_with_index.map { |rule, i| "(?<r#{i}>#{rule.source.sub("?<value>", "?<v#{i}>")})" }
         .join("|"),
    Regexp::MULTILINE
  ).freeze

  LABELS = RULES.map { |rule| "[#{rule.kind.upcase}]" }.freeze

  # Redact `text`, matching the Rust engine's output byte for byte.
  def self.scrub(text)
    text.gsub(COMBINED) do
      match = Regexp.last_match
      index = RULES.each_index.find { |i| match["r#{i}"] }
      next match[0] if index.nil?

      rule = RULES[index]
      value = rule.captures ? match["v#{index}"] : match[0]
      next match[0] if value.nil?
      next match[0] if rule.validator && !rule.validator.call(value)

      if rule.captures
        # Splice by offset, not by `sub`: `password=password` would otherwise
        # replace the key instead of the value.
        from, to = match.offset("v#{index}")
        base = match.begin(0)
        match[0][0, from - base] + LABELS[index] + match[0][(to - base)..]
      else
        LABELS[index]
      end
    end
  end
end
