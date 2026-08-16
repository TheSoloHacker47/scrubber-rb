# frozen_string_literal: true

require_relative "lib/scrubber/version"

Gem::Specification.new do |spec|
  spec.name = "scrubber_rb"
  spec.version = Scrubber::VERSION
  spec.authors = ["Nikhil Nelson"]
  spec.email = ["thesolohacker47@gmail.com"]

  spec.summary = "Fast PII and secret redaction for Ruby, with a Rust core."
  spec.description = <<~DESC.gsub(/\s+/, " ").strip
    Redact emails, phone numbers, credit cards, SSNs, IBANs, IPs, JWTs, API keys,
    private keys and Indian IDs (Aadhaar/PAN/UPI) from any string in a single pass
    through a Rust engine. Checksum-validated (Luhn, Verhoeff, mod-97) so random
    numbers are not mistaken for card numbers, and ReDoS-immune by construction.
    Ships a Rails log formatter, Rack middleware and an LLM prompt guard.
  DESC

  spec.homepage = "https://github.com/TheSoloHacker47/scrubber-rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"
  spec.required_rubygems_version = ">= 3.3.11"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["documentation_uri"] = "#{spec.homepage}#readme"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*.rb",
    "ext/**/*.{rs,rb,toml,lock}",
    "Cargo.toml",
    "Cargo.lock",
    "sig/**/*.rbs",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "SECURITY.md"
  ]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/scrubber_rb/extconf.rb"]

  # Only needed when building from source. The cross-compiled platform gems
  # ship a prebuilt library and drop this dependency.
  spec.add_dependency "rb_sys", "~> 0.9.91"
end
