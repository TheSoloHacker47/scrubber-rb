# frozen_string_literal: true

require "simplecov"
SimpleCov.start do
  add_filter "/spec/"
  add_filter "/benchmark/"
  # The whole point of the gem lives in ext/; lib/ is the thin Ruby shell, so
  # hold it to a high bar.
  minimum_coverage 90 if ENV["COVERAGE"]
end

require "scrubber_rb"
require_relative "support/vectors"

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  config.filter_run_when_matching :focus
  config.example_status_persistence_file_path = ".rspec_status"
  Kernel.srand config.seed

  config.include Vectors

  config.before { Scrubber.reset! }
end
