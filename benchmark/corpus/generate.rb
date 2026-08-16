#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates a synthetic log corpus for the benchmarks.
#
#   ruby benchmark/corpus/generate.rb            # 100MB, seed 42
#   SIZE_MB=10 SEED=7 ruby benchmark/corpus/generate.rb
#
# Seeded, so the same command always produces the same bytes and two benchmark
# runs on different machines are comparable. The mix is meant to look like a
# real production log rather than a wall of credit cards: roughly 12% of lines
# carry something sensitive, which is about what a busy Rails app looks like.
# Making that number higher would flatter the Rust engine, since the pure-Ruby
# baseline is fastest on lines with no matches at all.

require "fileutils"

SIZE_MB = Integer(ENV.fetch("SIZE_MB", "100"))
SEED = Integer(ENV.fetch("SEED", "42"))
OUT = ENV.fetch("CORPUS", File.expand_path("production.log", __dir__))

rng = Random.new(SEED)

HOSTS = %w[web-01 web-02 worker-03 api-07 sidekiq-01].freeze
PATHS = %w[/ /orders /users/42 /api/v1/charges /health /assets/app-4f3c2b1a.js
           /admin/reports /webhooks/stripe].freeze
VERBS = %w[GET POST PUT PATCH DELETE].freeze
LEVELS = %w[INFO INFO INFO DEBUG WARN ERROR].freeze
NAMES = %w[nik priya alex sam jordan taylor rahul mei omar chen].freeze
DOMAINS = %w[example.com example.org test.co.uk mail.example.net acme.io].freeze

# Luhn-valid card numbers, generated rather than copied.
def luhn_complete(prefix, length, rng)
  body = prefix + Array.new(length - prefix.length - 1) { rng.rand(10) }.join
  sum = 0
  body.reverse.each_char.with_index do |ch, i|
    v = ch.to_i
    if i.even?
      v *= 2
      v -= 9 if v > 9
    end
    sum += v
  end
  body + ((10 - (sum % 10)) % 10).to_s
end

BENIGN = lambda do |rng|
  [
    -> { "#{rng.rand(1..999)}.#{rng.rand(999)}ms Completed 200 OK (Views: #{rng.rand(50)}ms)" },
    -> { "#{VERBS.sample(random: rng)} #{PATHS.sample(random: rng)} 200 #{rng.rand(9999)}" },
    -> { "Cache hit rate 0.#{rng.rand(1000).to_s.rjust(4, "0")} over #{rng.rand(1 << 20)} keys" },
    -> { "Sidekiq job OrderMailer##{rng.rand(1000)} done in #{rng.rand(5000)}ms" },
    -> { "Deployed sha #{rng.bytes(20).unpack1("H*")}" },
    -> { "ActiveRecord::RecordNotFound in OrdersController#show" },
    -> { "Migrating to AddIndexToOrders (2026081#{rng.rand(10)}091233)" }
  ].sample(random: rng).call
end

SENSITIVE = lambda do |rng|
  [
    -> { "user #{NAMES.sample(random: rng)}#{rng.rand(999)}@#{DOMAINS.sample(random: rng)} signed in" },
    -> { "charge card #{luhn_complete("4", 16, rng).scan(/\d{4}/).join(" ")} approved" },
    -> { "charge card #{luhn_complete("5", 16, rng)} declined" },
    -> { "callback token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI#{rng.rand(1 << 30)}In0.#{rng.bytes(24).unpack1("H*")}" },
    -> { "aws key AKIA#{Array.new(16) { ("A".."Z").to_a.sample(random: rng) }.join} rotated" },
    -> { "db connect postgres://app:#{rng.bytes(8).unpack1("H*")}@db-#{rng.rand(9)}.internal:5432/prod" },
    -> { "login attempt password=#{rng.bytes(6).unpack1("H*")} failed" },
    -> { "peer #{rng.rand(256)}.#{rng.rand(256)}.#{rng.rand(256)}.#{rng.rand(256)} disconnected" },
    -> { "ssn on file #{rng.rand(1..899).to_s.rjust(3, "0")}-#{rng.rand(1..99).to_s.rjust(2, "0")}-#{rng.rand(1..9999).to_s.rjust(4, "0")}" },
    -> { "call back +1#{rng.rand(2..9)}#{rng.rand(10**8).to_s.rjust(8, "0")}" },
    -> { "github token ghp_#{Array.new(36) { [*"a".."z", *"0".."9"].sample(random: rng) }.join}" },
    -> { "nic 00:#{format("%02x", rng.rand(256))}:#{format("%02x", rng.rand(256))}:#{format("%02x", rng.rand(256))}:#{format("%02x", rng.rand(256))}:#{format("%02x", rng.rand(256))} up" }
  ].sample(random: rng).call
end

# Roughly one line in eight carries something worth redacting.
SENSITIVE_RATE = 0.12

target = SIZE_MB * 1024 * 1024
FileUtils.mkdir_p(File.dirname(OUT))

written = 0
lines = 0
buffer = +""

File.open(OUT, "wb") do |file|
  while written < target
    host = HOSTS.sample(random: rng)
    level = LEVELS.sample(random: rng)
    body = rng.rand < SENSITIVE_RATE ? SENSITIVE.call(rng) : BENIGN.call(rng)
    line = "2026-08-16T#{format("%02d:%02d:%02d", rng.rand(24), rng.rand(60), rng.rand(60))}." \
           "#{format("%06d", rng.rand(1_000_000))} #{host} [#{level}] #{body}\n"

    buffer << line
    written += line.bytesize
    lines += 1

    if buffer.bytesize > 4 * 1024 * 1024
      file.write(buffer)
      buffer.clear
    end
  end
  file.write(buffer)
end

puts "wrote #{OUT}"
puts "  #{(File.size(OUT) / 1024.0 / 1024).round(1)} MB, #{lines} lines, seed #{SEED}"
