# frozen_string_literal: true

module Scrubber
  # A compiled, immutable scrubber.
  #
  # Compiling ~35 regexes into one automaton is the expensive part; scanning is
  # cheap. Build one of these at boot and reuse it forever:
  #
  #   SCRUBBER = Scrubber.new(replacement: :hash)
  #   SCRUBBER.scrub(line)
  #
  # Instances are frozen and hold no per-call state, so a single instance is
  # safe to share across every thread in the process.
  class Instance
    REPLACEMENTS = %i[label mask hash remove].freeze

    # Read in 1MB slices, and never cut closer than this to the end of the
    # buffer, so a match straddling a chunk boundary still sees both halves.
    CHUNK_SIZE = 1024 * 1024
    CARRY_SIZE = 8 * 1024

    attr_reader :detectors, :custom, :replacement, :hash_salt

    def initialize(detectors: Scrubber::DEFAULTS, custom: {}, replacement: :label, hash_salt: nil)
      @detectors = normalize_detectors(detectors)
      @custom = normalize_custom(custom)
      @replacement = normalize_replacement(replacement)
      @hash_salt = hash_salt&.to_s

      @native = Native.new(
        @detectors.map(&:to_s),
        @custom.map { |name, regexp| [name.to_s, regexp.source, regexp.options] },
        @replacement.to_s,
        @hash_salt
      )
      freeze
    end

    # Redact every match in `text`, returning a new String with the same
    # encoding. The input is never mutated, and frozen input is fine.
    def scrub(text)
      str = coerce(text)
      replaced = @native.scrub(str)
      return str.dup if replaced.nil?

      replaced.force_encoding(str.encoding)
    end

    # Redact in place. Returns the same object, so it raises FrozenError on a
    # frozen string exactly like every other Ruby bang method.
    def scrub!(text)
      str = coerce(text)
      replaced = @native.scrub(str)
      return str if replaced.nil?

      str.replace(replaced.force_encoding(str.encoding))
    end

    # Find matches without replacing them.
    #
    #   Scrubber.detect("mail nik@example.com")
    #   # => [#<Scrubber::Match type=:email 5...20 preview="n**@e******.com">]
    #
    # Offsets are character offsets into `text`, not byte offsets, so they index
    # the Ruby string correctly even when it contains emoji or Devanagari.
    def detect(text)
      str = coerce(text)
      # Only UTF-8 needs byte->character conversion; in single-byte encodings
      # the two are the same number.
      char_offsets = str.encoding == Encoding::UTF_8
      @native.detect(str, char_offsets).map do |type, from, to, preview|
        Match.new(type: type.to_sym, begin: from, end: to, preview: preview)
      end
    end

    # True if anything at all would be redacted. Cheaper than `scrub` when you
    # only need a yes/no (an audit check, a test assertion, a CI gate).
    def match?(text)
      # `detect` stops at the match list; it never builds the output string.
      !@native.detect(coerce(text), false).empty?
    end

    # Stream a file through the engine.
    #
    # Reads in 1MB chunks and cuts each chunk at the last line break before an
    # 8KB carry window, so a match spanning a chunk boundary is never sliced in
    # half. Multi-line PEM blocks get an extra guard: if a chunk would end
    # between BEGIN and END, the cut moves back before the BEGIN.
    #
    # Returns the number of bytes written.
    def scrub_file(input_path, output_path, chunk_size: CHUNK_SIZE)
      written = 0
      File.open(input_path, "rb") do |input|
        File.open(output_path, "wb") do |output|
          each_safe_chunk(input, chunk_size) do |chunk|
            written += output.write(@native.scrub(chunk) || chunk)
          end
        end
      end
      written
    end

    # How many compiled patterns back this instance. Detectors expand to more
    # than one rule each in a few cases (`:api_key` alone is ~19).
    def rule_count
      @native.rule_count
    end

    def inspect
      "#<Scrubber::Instance detectors=#{@detectors.size} rules=#{rule_count} " \
        "replacement=#{@replacement.inspect}>"
    end

    # Config identity, used to memoize module-level `Scrubber.scrub` calls.
    def cache_key
      self.class.cache_key(
        detectors: @detectors, custom: @custom,
        replacement: @replacement, hash_salt: @hash_salt
      )
    end

    def self.cache_key(detectors:, custom:, replacement:, hash_salt:)
      customs = custom.to_a.map do |name, regexp|
        source = regexp.respond_to?(:source) ? regexp.source : regexp.to_s
        options = regexp.respond_to?(:options) ? regexp.options : 0
        [name.to_sym, source, options]
      end
      [Array(detectors).map(&:to_sym).sort, customs.sort, replacement.to_sym, hash_salt&.to_s]
    end

    private

    def coerce(text)
      return text if text.is_a?(String)
      raise TypeError, "expected a String, got #{text.class}" unless text.respond_to?(:to_str)

      text.to_str
    end

    def normalize_detectors(detectors)
      list = Array(detectors).map do |d|
        unless d.respond_to?(:to_sym)
          raise ConfigurationError,
                "detector names must be Symbols or Strings, got #{d.class}"
        end

        d.to_sym
      end
      list.uniq.freeze
    end

    def normalize_custom(custom)
      raise ConfigurationError, "custom: must be a Hash of name => Regexp" unless custom.respond_to?(:to_h)

      custom.to_h.each_with_object({}) do |(name, regexp), out|
        unless regexp.is_a?(Regexp)
          raise ConfigurationError,
                "custom detector #{name.inspect} must be a Regexp, got #{regexp.class}"
        end

        out[name.to_sym] = regexp
      end.freeze
    end

    def normalize_replacement(replacement)
      sym = replacement.to_sym
      unless REPLACEMENTS.include?(sym)
        raise ConfigurationError,
              "unknown replacement #{replacement.inspect}. Expected one of: #{REPLACEMENTS.join(", ")}"
      end

      sym
    end

    # Yields byte slices that are safe to scan independently.
    def each_safe_chunk(input, chunk_size)
      buffer = +""
      buffer.force_encoding(Encoding::BINARY)

      while (chunk = input.read(chunk_size))
        buffer << chunk
        next if buffer.bytesize <= CARRY_SIZE

        cut = safe_cut(buffer)
        next if cut.zero?

        yield buffer.byteslice(0, cut)
        buffer = buffer.byteslice(cut, buffer.bytesize - cut)
      end

      yield buffer unless buffer.empty?
    end

    # Where can this buffer be cut without slicing a match in half?
    def safe_cut(buffer)
      limit = buffer.bytesize - CARRY_SIZE
      return 0 if limit <= 0

      cut = buffer.rindex("\n", limit - 1)
      cut = cut ? cut + 1 : limit
      pem_safe_cut(buffer, cut)
    end

    # A PEM block can be longer than the carry window, so cutting at a line
    # break is not enough: if the head we are about to emit opens a block it
    # does not close, back the cut up to just before that BEGIN.
    def pem_safe_cut(buffer, cut)
      # Give up on the guard rather than buffer a whole file: a PEM block this
      # big is malformed, and unbounded memory growth is the worse failure.
      return cut if buffer.bytesize > CHUNK_SIZE * 8

      head = buffer.byteslice(0, cut)
      opens = head.scan("-----BEGIN").size
      closes = head.scan("-----END").size
      return cut if opens <= closes

      last_begin = head.rindex("-----BEGIN")
      return cut if last_begin.nil? || last_begin.zero?

      last_begin
    end
  end
end
