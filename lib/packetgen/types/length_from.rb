# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Types
    # This module is a mixin adding +length_from+ capacity to a type.
    # +length_from+ capacity is the capacity, for a type, to gets its
    # length from another object.
    # @author Sylvain Daubert
    # @since 3.0.0
    module LengthFrom
      # Max value returned by {#sz_to_read}.
      MAX_SZ_TO_READ = 65_535

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
        s[0, sz_to_read]
      end

      # Size to read, from length_from
      # @return [Integer]
      def sz_to_read
        len = case @length_from
              when Types::Int
                @length_from.to_i
              when Proc
                @length_from.call
              else
                MAX_SZ_TO_READ
              end
        [0, len].max
      end
    end
  end
end
