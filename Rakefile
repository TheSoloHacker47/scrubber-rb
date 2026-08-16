# frozen_string_literal: true

require "bundler/gem_tasks"
require "rb_sys/extensiontask"

GEMSPEC = Gem::Specification.load("scrubber_rb.gemspec")

RbSys::ExtensionTask.new("scrubber_rb", GEMSPEC) do |ext|
  ext.lib_dir = "lib/scrubber_rb"
  ext.cross_compile = true
end

# Guarded: the cross-compile containers install only what the build needs, so
# requiring RSpec unconditionally turns any build failure into a LoadError that
# hides the real one.
begin
  require "rspec/core/rake_task"
  RSpec::Core::RakeTask.new(:spec)
rescue LoadError
  desc "rspec is not available in this bundle"
  task(:spec) { abort "rspec is not installed; run `bundle install`" }
end

begin
  require "rubocop/rake_task"
  RuboCop::RakeTask.new
rescue LoadError
  desc "rubocop is not installed"
  task(:rubocop) { warn "rubocop is not available in this bundle" }
end

namespace :cargo do
  desc "Run the Rust unit tests"
  task :test do
    sh "cargo test --features link-ruby"
  end

  desc "Lint the Rust core"
  task :clippy do
    sh "cargo clippy --all-targets --features link-ruby -- -D warnings"
  end

  desc "Check Rust formatting"
  task :fmt do
    sh "cargo fmt --all -- --check"
  end
end

desc "Everything CI runs, in CI's order"
task ci: ["cargo:fmt", "cargo:clippy", "cargo:test", :compile, :spec, :rubocop]

desc "Generate the synthetic benchmark corpus (SIZE_MB=100)"
task :corpus do
  ruby "benchmark/corpus/generate.rb"
end

desc "Run the benchmark suite and print the README table"
task benchmark: :compile do
  ruby "benchmark/run.rb"
end

desc "Compare against logstop on the subset it covers"
task "benchmark:logstop" => :compile do
  ruby "benchmark/vs_logstop.rb"
end

desc "Assert the Rust engine is at least PERF_FLOOR (default 5) times the pure-Ruby reference"
task "benchmark:gate" => :compile do
  ruby "benchmark/gate.rb"
end

task build: :compile
task default: %i[compile spec]
