# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require 'forwardable'

module PacketGen
  module Types
    # This class handles null-terminated strings (aka C strings).
    # @author Sylvain Daubert
    # @since 3.1.6 no more a subclass or regular String
    class CString
      extend Forwardable
      include Fieldable

      def_delegators :@string, :[], :length, :size, :inspect, :==,
                     :unpack, :force_encoding, :encoding, :index, :empty?,
                     :encode, :slice, :slice!

      # @return [::String]
      attr_reader :string
      # @return [Integer]
      attr_reader :static_length

      # @param [Hash] options
      # @option options [Integer] :static_length set a static length for this string
      def initialize(options={})
        register_internal_string(+'')
        @static_length = options[:static_length]
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = str.to_s
        s = s[0, static_length] if static_length?
        register_internal_string s
        remove_null_character
        self
      end

      # get null-terminated string
      # @return [String]
      def to_s
        if static_length?
          s = string[0, static_length - 1]
          s << "\x00" * (static_length - s.length)
        else
          s = "#{string}\x00"
        end
        PacketGen.force_binary(s)
      end

      # Append the given string to CString
      # @param [#to_s] str
      # @return [self]
      def <<(str)
        @string << str.to_s
        remove_null_character
        self
      end

      # @return [Integer]
      def sz
        if static_length?
          static_length
        else
          to_s.size
        end
      end

      # Say if a static length is defined
      # @return [Boolean]
      # @since 3.1.6
      def static_length?
        !static_length.nil?
      end

      # Populate CString from a human readable string
      # @param [String] str
      # @return [self]
      def from_human(str)
        read str
      end

      # @return [String]
      def to_human
        string
      end

      private

      def register_internal_string(str)
        @string = str
        PacketGen.force_binary(@string)
      end

      def remove_null_character
        idx = string.index(0.chr)
        register_internal_string(string[0, idx]) unless idx.nil?
      end
    end
  end
end
