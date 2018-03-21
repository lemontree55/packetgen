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
        str_end = case @length_from
                  when Types::Int
                    str_end = @length_from.to_i
                  when Proc
                    str_end = @length_from.call
                  else
                    if @static_length.is_a? Integer
                      str_end = @static_length
                    else
                      str_end = s.size
                    end
                  end
        str_end = 0 if str_end < 0
        self.replace(s[0, str_end])
        self
      end

      alias sz length
      alias to_human to_s
    end
  end
end
