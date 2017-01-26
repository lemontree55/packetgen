module BindingHelper

  class KnowHeaderMatcher

    def initialize(header)
      @header = header
      @args = nil
    end

    def matches?(prev_header)
      @prev_header = prev_header
      result = prev_header.known_headers.keys.include?(@header)
      if @args and @args.is_a? Hash
        bindings = prev_header.known_headers[@header]
        @args.each do |key, value|
          bresult = if bindings.op == :or
                      bindings.one? { |b| b.key == key && b.value == value }
                    else
                      bindings.all? { |b| b.key == key && b.value == value }
                    end
          @bad_args = { key: key, value: value} unless bresult
          result &&= bresult
          break unless bresult
        end
      end
      result
    end

    def failure_message
      str = "expected #@header to be a known header from #{@prev_header}"
      if @bad_args
        str << "\n         expected: #{@bad_args.inspect}"
        str << "\nto be included in: " \
               "#{@prev_header.known_headers[@header].map(&:to_h).inspect}"
      end
      str
    end

    def with(args)
      @args = args
      self
    end
  end

  def know_header(header)
    KnowHeaderMatcher.new header
  end
end
