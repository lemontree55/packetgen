# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # This class is just like regular String. It only adds {#read} and {#sz} methods
    # to be compatible with others {Types}.
    # @author Sylvain Daubert
    class String < ::String

      # @param [String] str
      # @param [Hash] options
      # @option options [Types::Int,Proc] :length_from object or proc from which
      #   takes length when reading
      # @option options [Integer] :static_length set a static length for this string
      def initialize(options={})
        super()
        @length_from = options[:length_from]
        @static_length = options[:static_length]
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = str.to_s
        s = case @length_from
            when Types::Int
              s[0, @length_from.to_i]
            when Proc
              s[0, @length_from.call]
            else
              if @static_length.is_a? Integer
                s[0, @static_length]
              else
                s
              end
            end
        self.replace s
        self
      end

      alias sz length
    end
  end
end
