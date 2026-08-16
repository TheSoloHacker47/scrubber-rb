# frozen_string_literal: true

require "bundler/gem_tasks"
require "rb_sys/extensiontask"

# musl static-links the C runtime by default, and a static CRT cannot produce a
# shared library, so cargo refuses to build the cdylib at all:
#
#   error: cannot produce cdylib for `scrubber_rb` as the target
#   `x86_64-unknown-linux-musl` does not support these crate types
#
# See rust-lang/cargo#10143. The flag has to be in the *environment*. Cargo
# decides whether a target supports a crate type while probing that target,
# before rustc is invoked, so anything appended after `cargo rustc --` (which
# is what rb_sys does) arrives too late to matter. RUSTFLAGS also outranks
# `target.*.rustflags` from .cargo/config.toml, so if something else in the
# build container sets it, the config file is ignored — hence setting it here,
# where rake spawns make which spawns cargo, and the environment is inherited
# the whole way down.
#
# .cargo/config.toml stays for `gem install` on Alpine, which never runs this
# Rakefile and where nothing sets RUSTFLAGS.
musl = ENV["RUBY_TARGET"].to_s.include?("musl") ||
       RbConfig::CONFIG["host_os"].to_s.include?("musl") ||
       RbConfig::CONFIG["arch"].to_s.include?("musl")

if musl
  crt = "-C target-feature=-crt-static"
  before = ENV["RUSTFLAGS"].to_s
  ENV["RUSTFLAGS"] = before.include?(crt) ? before : "#{crt} #{before}".strip
  warn "scrubber_rb: musl target; RUSTFLAGS was #{before.inspect}, now #{ENV["RUSTFLAGS"].inspect}"
end

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
