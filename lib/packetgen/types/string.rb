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
    # This class mimics regular String, but it is {Fieldable}.
    # @author Sylvain Daubert
    # @since 3.1.6 no more a subclass or regular String
    class String
      extend Forwardable
      include Fieldable
      include LengthFrom

      def_delegators :@string, :[], :to_s, :length, :size, :inspect, :==,
                     :unpack, :force_encoding, :encoding, :index, :empty?,
                     :encode, :slice, :slice!, :[]=

      # @return [::String]
      attr_reader :string
      # @return [Integer]
      attr_reader :static_length

      # @param [Hash] options
      # @option options [Types::Int,Proc] :length_from object or proc from which
      #   takes length when reading
      # @option options [Integer] :static_length set a static length for this string
      def initialize(options={})
        register_internal_string(+'')
        initialize_length_from(options)
        @static_length = options[:static_length]
      end

      def initialize_copy(_orig)
        @string = @string.dup
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = read_with_length_from(str)
        register_internal_string s
        self
      end

      alias old_sz_to_read sz_to_read
      private :old_sz_to_read

      # Size to read.
      # Computed from static_length or length_from, if defined.
      # @return [Integer]
      # @since 3.1.6
      def sz_to_read
        return static_length if static_length?

        old_sz_to_read
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

      # Append the given string to String
      # @param [#to_s] str
      # @return [self]
      def <<(str)
        @string << str.to_s
        self
      end

      alias sz length
      alias to_human to_s
      alias from_human read

      private

      def register_internal_string(str)
        @string = str
        PacketGen.force_binary(@string)
      end
    end
  end
end
