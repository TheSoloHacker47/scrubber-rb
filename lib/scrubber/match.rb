# frozen_string_literal: true

module Scrubber
  # One thing the engine found, without the thing itself.
  #
  # `begin` and `end` are character offsets into the string you passed, so
  # `text[match.begin...match.end]` gives you the raw value back if you really
  # want it. `preview` is already masked — it exists so you can log "we found an
  # email here" without logging the email.
  Match = Struct.new(:type, :begin, :end, :preview, keyword_init: true) do
    # The span as a Range, ready for `String#[]`.
    def to_range
      self.begin...self.end
    end

    # Length of the match in characters.
    def length
      self.end - self.begin
    end

    def inspect
      "#<Scrubber::Match type=#{type.inspect} #{self.begin}...#{self.end} " \
        "preview=#{preview.inspect}>"
    end
    alias_method :to_s, :inspect
  end
end
