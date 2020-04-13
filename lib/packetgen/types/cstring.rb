# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types
    # This class handles null-terminated strings (aka C strings).
    # @author Sylvain Daubert
    # @since 3.1.6 no more a subclass or regular String
    class CString
      extend Forwardable
      include Fieldable

      def_delegators :@string, :[], :length, :size, :inspect, :==, :<<,
                     :unpack, :force_encoding, :encoding, :index

      # @return [::String]
      attr_reader :string
      # @return [Integer]
      attr_reader :static_length

      # @param [Hash] options
      # @option options [Integer] :static_length set a static length for this string
      def initialize(options={})
        set_internal_string ''
        @static_length = options[:static_length]
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = str.to_s
        s = s[0, static_length] if static_length?
        idx = s.index(0.chr)
        s = s[0, idx] unless idx.nil?
        set_internal_string s
        self
      end

      # get null-terminated string
      # @return [String]
      def to_s
        if static_length?
          s = string[0, static_length - 1]
          s << "\0" * (static_length - s.length)
        else
          s = string + "\x00"
        end
        PacketGen.force_binary(s)
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
        idx = self.index(+"\x00".encode(self.encoding)) || self.sz
        self[0, idx]
      end

      private

      def set_internal_string(str)
        @string = str
        force_binary(@string)
      end
    end
  end
end
