# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Types
    # This class is just like regular String. It only adds {#read}, {#sz},
    # #{to_human} and {#from_human} methods
    # to be compatible with others {Types}.
    # @author Sylvain Daubert
    class String < ::String
      include LengthFrom

      # @return [Integer]
      attr_reader :static_length

      # @param [Hash] options
      # @option options [Types::Int,Proc] :length_from object or proc from which
      #   takes length when reading
      # @option options [Integer] :static_length set a static length for this string
      def initialize(options={})
        super()
        initialize_length_from(options)
        @static_length = options[:static_length]
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = read_with_length_from(str)
        s = s[0, static_length] if static_length
        self.replace(s)
        self
      end

      alias sz length
      alias to_human to_s
      alias from_human read
    end
  end
end
