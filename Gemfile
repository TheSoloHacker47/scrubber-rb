# frozen_string_literal: true

source "https://rubygems.org"

gemspec

gem "rake", "~> 13.0"
gem "rake-compiler", "~> 1.2"
gem "rb_sys", "~> 0.9.91"

group :development, :test do
  gem "benchmark-ips", "~> 2.13"
  gem "rack", ">= 2.2"
  gem "rspec", "~> 3.13"
  gem "rubocop", "~> 1.66"
  gem "rubocop-rspec", "~> 3.0"
  gem "simplecov", "~> 0.22", require: false
end

group :benchmark do
  # The incumbent we benchmark against. Narrower scope (log filtering only) —
  # see benchmark/vs_logstop.rb for what is and is not comparable.
  gem "logstop", "~> 0.3", require: false
end
