# frozen_string_literal: true

require "spec_helper"
require "tmpdir"

RSpec.describe "Scrubber.scrub_file" do
  around do |example|
    Dir.mktmpdir("scrubber") do |dir|
      @dir = dir
      example.run
    end
  end

  def write(name, content)
    path = File.join(@dir, name)
    File.binwrite(path, content)
    path
  end

  def run(content, **options)
    input = write("in.log", content)
    output = File.join(@dir, "out.log")
    Scrubber.scrub_file(input, output, **options)
    File.binread(output)
  end

  it "redacts a small file" do
    expect(run("user nik@example.com\n")).to eq("user [EMAIL]\n")
  end

  it "returns the number of bytes written" do
    input = write("in.log", "user nik@example.com\n")
    output = File.join(@dir, "out.log")

    expect(Scrubber.scrub_file(input, output)).to eq(File.size(output))
  end

  it "handles an empty file" do
    expect(run("")).to eq("")
  end

  it "leaves a clean file byte-identical" do
    content = "nothing to see here\n" * 500
    expect(run(content)).to eq(content)
  end

  it "preserves everything that is not a match" do
    content = "prefix nik@example.com suffix\n"
    expect(run(content)).to eq("prefix [EMAIL] suffix\n")
  end

  describe "chunk boundaries" do
    # A tiny chunk size forces the carry-window logic to run on every line,
    # which is the only way to test it without writing a 100MB fixture.
    let(:tiny) { 64 }

    it "does not lose matches that straddle a chunk boundary" do
      content = (1..400).map { |i| "line #{i} user#{i}@example.com pad\n" }.join
      result = run(content, chunk_size: tiny)

      expect(result.scan("[EMAIL]").size).to eq(400)
      expect(result).not_to include("@example.com")
    end

    it "produces the same output as scrubbing the whole string at once" do
      content = (1..200).map { |i| "row #{i} card #{valid_cards[:visa]} ip 10.0.#{i % 256}.1\n" }.join

      expect(run(content, chunk_size: tiny)).to eq(Scrubber.scrub(content))
    end

    it "keeps a multi-line private key block intact across chunks" do
      content = "before\n#{private_key}after\n"
      result = run(content, chunk_size: tiny)

      expect(result).to include("[PRIVATE_KEY]")
      expect(result).not_to include("MIIEpAIBAAKCAQEA")
      expect(result).to eq(Scrubber.scrub(content))
    end

    it "handles a file with no line breaks at all" do
      content = "nik@example.com " * 500
      expect(run(content, chunk_size: tiny).scan("[EMAIL]").size).to eq(500)
    end

    it "handles a file that does not end in a newline" do
      expect(run("user nik@example.com", chunk_size: tiny)).to eq("user [EMAIL]")
    end
  end

  describe "binary safety" do
    it "passes invalid UTF-8 bytes through untouched" do
      content = (+"log \xFF\xFE nik@example.com\n").b
      result = run(content)

      expect(result.bytes).to include(0xFF, 0xFE)
      expect(result).to include("[EMAIL]")
    end

    it "does not corrupt multibyte characters at a chunk boundary" do
      content = ("नमस्ते nik@example.com 🎉\n" * 50).dup
      result = run(content, chunk_size: 64).force_encoding("UTF-8")

      expect(result).to be_valid_encoding
      expect(result.scan("[EMAIL]").size).to eq(50)
      expect(result.scan("🎉").size).to eq(50)
    end
  end

  it "accepts the same options as Scrubber.scrub" do
    result = run("user nik@example.com\n", replacement: :hash)
    expect(result).to match(/\Auser \[EMAIL:[0-9a-f]{8}\]\n\z/)
  end

  it "works through a reusable instance" do
    scrubber = Scrubber.new(detectors: [:email])
    input = write("in.log", "user nik@example.com card #{valid_cards[:visa]}\n")
    output = File.join(@dir, "out.log")
    scrubber.scrub_file(input, output)

    result = File.binread(output)
    expect(result).to include("[EMAIL]")
    expect(result).to include(valid_cards[:visa])
  end

  it "raises a normal Errno for a missing input file" do
    expect { Scrubber.scrub_file(File.join(@dir, "nope.log"), File.join(@dir, "out.log")) }
      .to raise_error(Errno::ENOENT)
  end
end
