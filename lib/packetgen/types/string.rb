# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types
    # This class mimics regular String, but it is {Fieldable}.
    # @author Sylvain Daubert
    # @since 3.1.6 no more a subclass or regular String
    class String
      extend Forwardable
      include Fieldable
      include LengthFrom

      def_delegators :@string, :[], :to_s, :length, :size, :inspect, :==, :<<,
                     :unpack, :force_encoding, :encoding, :index

      # @return [::String]
      attr_reader :string
      # @return [Integer]
      attr_reader :static_length

      # @param [Hash] options
      # @option options [Types::Int,Proc] :length_from object or proc from which
      #   takes length when reading
      # @option options [Integer] :static_length set a static length for this string
      def initialize(options={})
        set_internal_string ''
        initialize_length_from(options)
        @static_length = options[:static_length]
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = read_with_length_from(str)
        s = s[0, static_length] if static_length?
        set_internal_string s
        self
      end

      # Say if a static length is defined
      # @return [Boolean]
      # @since 3.1.6
      def static_length?
        !static_length.nil?
      end

      def format_inspect
        inspect
      end

      alias sz length
      alias to_human to_s
      alias from_human read

      private

      def set_internal_string(str)
        @string = str
        force_binary(@string)
      end
    end
  end
end
