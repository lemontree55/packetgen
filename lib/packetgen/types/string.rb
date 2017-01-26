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
      # @option options [Types::Int] :length_from object from which takes length when
      #   reading
      def initialize(str='', options={})
        super(str)
        @length_from = options[:length_from]
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = str.to_s
        s = s[0, @length_from.to_i] unless @length_from.nil?
        self.replace s
        self
      end

      alias sz length
    end
  end
end
