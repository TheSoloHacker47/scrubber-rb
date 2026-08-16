# frozen_string_literal: true

require "spec_helper"
require "rack"

RSpec.describe Scrubber::Middleware do
  let(:app) { ->(_env) { [200, { "content-type" => "text/plain" }, ["ok"]] } }
  let(:middleware) { described_class.new(app) }

  def get(path)
    Rack::MockRequest.new(middleware).get(path)
  end

  def env_for(path)
    captured = nil
    inspector = described_class.new(lambda { |env|
      captured = env.dup
      [200, {}, ["ok"]]
    })
    Rack::MockRequest.new(inspector).get(path)
    captured
  end

  it "passes the request through untouched" do
    response = get("/login?user=nik&password=hunter2")
    expect(response.status).to eq(200)
    expect(response.body).to eq("ok")
  end

  it "does not rewrite QUERY_STRING, because the app needs the real value" do
    env = env_for("/login?user=nik&password=hunter2")
    expect(env["QUERY_STRING"]).to eq("user=nik&password=hunter2")
  end

  it "publishes a redacted query string for logging" do
    env = env_for("/login?user=nik&password=hunter2")

    expect(env["scrubber.query_string"]).to eq("user=nik&password=[PASSWORD_PAIR]")
  end

  it "publishes redacted params as a Hash" do
    env = env_for("/orders?email=nik%40example.com&qty=2")

    expect(env["scrubber.params"]).to eq("email" => "[EMAIL]", "qty" => "2")
  end

  it "exposes the engine for anything else the app wants to log" do
    env = env_for("/x?a=1")
    expect(env["scrubber.instance"]).to be_a(Scrubber::Instance)
  end

  it "adds nothing when there is no query string" do
    env = env_for("/health")
    expect(env).not_to have_key("scrubber.query_string")
  end

  it "does not raise on a malformed query string" do
    # Built by hand: Rack's own URI parser rejects this before the middleware
    # would ever see it, and the point is that *we* survive it.
    env = Rack::MockRequest.env_for("/x").merge("QUERY_STRING" => "%%%&=&&a&b=%zz")

    expect { middleware.call(env) }.not_to raise_error
    expect(env["scrubber.params"]).to be_a(Hash)
  end

  describe "exception messages" do
    let(:boom) do
      ->(_env) { raise "connect failed: postgres://app:hunter2@db/prod" }
    end

    it "redacts them before they reach an error tracker" do
      stack = described_class.new(boom)

      expect { stack.call(Rack::MockRequest.env_for("/x")) }
        .to raise_error(RuntimeError, /\[URL_CREDENTIALS\]/)
    end

    it "keeps the exception class so error groupers still group it" do
      stack = described_class.new(boom)
      stack.call(Rack::MockRequest.env_for("/x"))
    rescue StandardError => e
      expect(e).to be_a(RuntimeError)
      expect(e.backtrace).not_to be_nil
    end

    it "leaves clean exceptions exactly as they were" do
      original = RuntimeError.new("nothing sensitive")
      stack = described_class.new(->(_env) { raise original })

      expect { stack.call(Rack::MockRequest.env_for("/x")) }
        .to(raise_error { |e| expect(e).to equal(original) })
    end

    it "can be turned off" do
      stack = described_class.new(boom, scrub_exceptions: false)

      expect { stack.call(Rack::MockRequest.env_for("/x")) }
        .to raise_error(RuntimeError, /hunter2/)
    end
  end
end
