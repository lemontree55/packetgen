# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types
    # This module is a mixin adding +length_from+ capacity to a type.
    # +length_from+ capacity is the capacity, for a type, to gets its
    # length from another object.
    # @author Sylvain Daubert
    # @since 3.0.0
    module LengthFrom
      # Initialize +length from+ capacity.
      # Should be call by extensed object's initialize.
      # @param [Hash] options
      # @option options [Types::Int,Proc] :length_from object or proc from which
      #   takes length when reading
      # @return [void]
      def initialize_length_from(options)
        @length_from = options[:length_from]
      end

      # Return a substring from +str+ of length given in another object.
      # @param [#to_s] str
      # @return [String]
      def read_with_length_from(str)
        s = PacketGen.force_binary(str.to_s)
        str_end = case @length_from
                  when Types::Int
                    @length_from.to_i
                  when Proc
                    @length_from.call
                  else
                    s.size
                  end
        str_end = 0 if str_end.negative?
        s[0, str_end]
      end
    end
  end
end
