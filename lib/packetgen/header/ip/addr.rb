# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class IP
      # IP address, as a group of 4 bytes
      # @author Sylvain Daubert
      class Addr < BinStruct::Struct
        include BinStruct::Structable

        # @!attribute a1
        #  @return [Integer] IP address first byte
        define_attr :a1, BinStruct::Int8
        # @!attribute a2
        #  @return [Integer] IP address seconf byte
        define_attr :a2, BinStruct::Int8
        # @!attribute a3
        #  @return [Integer] IP address third byte
        define_attr :a3, BinStruct::Int8
        # @!attribute a4
        #  @return [Integer] IP address fourth byte
        define_attr :a4, BinStruct::Int8

        IPV4_ADDR_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.freeze

        # Read a dotted address
        # @param [String] str
        # @return [self]
        def from_human(str)
          return self if str.nil?

          m = str.match(IPV4_ADDR_REGEX)
          if m
            self[:a1].from_human(m[1].to_i)
            self[:a2].from_human(m[2].to_i)
            self[:a3].from_human(m[3].to_i)
            self[:a4].from_human(m[4].to_i)
          end
          self
        end

        # Addr in human readable form (dotted format)
        # @return [String]
        def to_human
          attributes.map { |f| self[f].to_i.to_s }.join('.')
        end

        # Addr as an integer
        # @return [Integer]
        def to_i
          (self.a1 << 24) | (self.a2 << 16) | (self.a3 << 8) |
            self.a4
        end

        # Return true if this address is a multicast one
        # @return [Boolean]
        def mcast?
          self.a1 >= 224 && self.a1 <= 239
        end

        def ==(other)
          other.is_a?(self.class) &&
            attributes.all? { |attr| self[attr].value == other[attr].value }
        end
      end
    end
  end
end
