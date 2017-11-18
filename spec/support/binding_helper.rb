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
        return false unless bindings
        if bindings.op == :or
          @args.each do |key, value|
            bresult = bindings.one? do |b|
              case b
              when PacketGen::Header::Base::Binding
                b.key == key && b.value == value
              when PacketGen::Header::Base::ProcBinding
                b.check?(prev_header.new(@args))
              end
            end
            @bad_args_or = { key: key, value: value} unless bresult
            result &&= bresult
            break unless bresult
          end
        else
          result = bindings.to_h == @args
          @bad_args_and = @args
        end
      end
      result
    end

    def failure_message
      str = "expected #@header to be a known header from #{@prev_header}"
      if @bad_args_or
        str << "\n         expected: #{@bad_args_or.inspect}"
        str << "\nto be included in: " \
               "#{@prev_header.known_headers[@header].inspect}"
      elsif @bad_args_and
        str << "\n  expected: #{@prev_header.known_headers[@header].to_h}"
        str << "\n       got: #{@bad_args_and.inspect}"
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

  def clear_bindings(klass)
    klass.known_headers.clear
  end
end
