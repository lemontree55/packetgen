# frozen_string_literal: true

module BindingHelper
  class KnowHeaderMatcher
    def initialize(header)
      @header = header
      @args = nil
    end

    def matches?(prev_header)
      @prev_header = prev_header
      result = prev_header.known_headers.key?(@header)
      if @args.is_a?(Hash)
        bindings = prev_header.known_headers[@header]
        return false unless bindings

        result &&= bindings.one? do |subbindings|
          subbindings.all? do |binding|
            if binding.is_a?(PacketGen::Header::Base::ProcBinding)
              keys = @args.keys
              struct = Struct.new(*keys)
              binding.check?(struct.new(*@args.values_at(*keys)))
            elsif binding.value.is_a?(Proc)
              binding.value.call(@args[binding.key])
            else
              binding.value == @args[binding.key]
            end
          end
        end
        @bad_args = @args
      end
      result
    end

    def failure_message
      str = +"expected #{@header} to be a known header from #{@prev_header}"
      if @bad_args
        str << "\n         expected: #{@bad_args.inspect}"
        str << "\nto be included in: " \
               "#{@prev_header.known_headers[@header].inspect}"
      end
      str
    end

    def failure_message_when_negated
      str = "expected #{@header} to not be a known header from #{@prev_header}"
      if @bad_args
        str << "\n        expected: #{@bad_args.inspect}"
        str << "\nto not be included in: " \
               "#{@prev_header.known_headers[@header].inspect}"
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

  def remove_binding(klass1, klass2)
    klass1.known_headers.delete(klass2)
    PacketGen::Header.remove_class(klass2)
  end
end
