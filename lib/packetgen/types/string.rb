# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # This class is just like regular String. It only adds #read and #sz methods
    # to be compatible with others {Types}.
    # @author Sylvain Daubert
    class String < ::String

      # @param [String] str
      # @param [Hash] options
      # @option options [Types::Int,Proc] :length_from object or proc from which
      #   takes length when reading
      def initialize(str='', options={})
        super(str)
        @length_from = options[:length_from]
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = str.to_s
        s = case @length_from
            when Int
              s[0, @length_from.to_i]
            else
              s
            end
        self.replace s
        self
      end

      alias sz length
    end
  end
end
