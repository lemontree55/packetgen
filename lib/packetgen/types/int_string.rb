# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Types

    # Provides a class for creating strings preceeded by their length as a {Int}.
    # By default, a null string will have one byte length (length byte set to 0).
    # @author Sylvain Daubert
    class IntString

      # internal string
      # @return [String]
      attr_reader :string

      # @param [Class] len_type should be a {Int} subclass
      # @param [::String] string
      def initialize(len_type=Int8, string: '')
        @string = Types::String.new.read(string)
        @length = len_type.new
        calc_length
      end

      # @param [::String] str
      # @return [IntString] self
      def read(str)
        unless str[0, @length.width].size == @length.width
          raise ParseError,
                "String too short for type #{@length.class.to_s.gsub(/.*::/, '')}"
        end
        @length.read str[0, @length.width]
        @string.read str[@length.width, @length.to_i]
        self
      end

      # @param [Integer] l
      # @return [Integer]
      def length=(l)
        @length.read l
        l
      end

      # @return [Integer]
      def length
        @length.to_i
      end

      # @param [#to_s] s
      # @return [String]
      def string=(s)
        @length.value = s.to_s.size
        @string = s.to_s
      end

      # Get binary string
      # @return [::String]
      def to_s
        @length.to_s << @string.to_s
      end

      # Get human readable string
      # @return [::String]
      # @since 2.2.0
      def to_human
        @string.to_s.inspect
      end

      # Set length from internal string length
      # @return [Integer]
      def calc_length
        @length.read @string.length
      end

      # Give binary string length (including +length+ field)
      # @return [Integer]
      def sz
        to_s.size
      end
    end
  end
end
