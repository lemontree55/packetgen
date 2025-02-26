# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require 'ipaddr'

module PacketGen
  module Header
    class IPv6
      # IPv6 address, as a group of 8 2-byte words
      # @author Sylvain Daubert
      class Addr < BinStruct::Struct
        include BinStruct::Structable

        # @!attribute a1
        #  1st 2-byte word of IPv6 address
        #  @return [Integer]
        define_attr :a1, BinStruct::Int16
        # @!attribute a2
        #  2nd 2-byte word of IPv6 address
        #  @return [Integer]
        define_attr :a2, BinStruct::Int16
        # @!attribute a3
        #  3rd 2-byte word of IPv6 address
        #  @return [Integer]
        define_attr :a3, BinStruct::Int16
        # @!attribute a4
        #  4th 2-byte word of IPv6 address
        #  @return [Integer]
        define_attr :a4, BinStruct::Int16
        # @!attribute a5
        #  5th 2-byte word of IPv6 address
        #  @return [Integer]
        define_attr :a5, BinStruct::Int16
        # @!attribute a6
        #  6th 2-byte word of IPv6 address
        #  @return [Integer]
        define_attr :a6, BinStruct::Int16
        # @!attribute a7
        #  7th 2-byte word of IPv6 address
        #  @return [Integer]
        define_attr :a7, BinStruct::Int16
        # @!attribute a8
        #  8th 2-byte word of IPv6 address
        #  @return [Integer]
        define_attr :a8, BinStruct::Int16

        # Read a colon-delimited address
        # @param [String] str
        # @return [self]
        # @raise [ArgumentError] not a colon-delimited IPv6 address
        def from_human(str)
          return self if str.nil?

          addr = IPAddr.new(str)
          raise ArgumentError, 'string is not a IPv6 address' unless addr.ipv6?

          addri = addr.to_i
          8.times do |i|
            self.send(:"a#{i + 1}=", addri >> (16 * (7 - i)) & 0xffff)
          end
          self
        end

        # Addr6 in human readable form (colon-delimited hex string)
        # @return [String]
        def to_human
          IPAddr.new(to_a.map { |a| a.to_i.to_s(16) }.join(':')).to_s
        end

        # Return an array of address 16-bit words
        # @return [Array<Integer>]
        def to_a
          @attributes.values
        end

        # Return true if this address is a multicast one
        # @return [Boolean]
        def mcast?
          self.a1 & 0xff00 == 0xff00
        end

        def ==(other)
          other.is_a?(self.class) &&
            attributes.all? { |attr| self[attr].value == other[attr].value }
        end
      end

      # Class to handle series of IPv6 addresses
      # @author Sylvain Daubert
      class ArrayOfAddr < BinStruct::Array
        set_of IPv6::Addr

        # Push a IPv6 address to the array
        # @param [String,Addr] addr
        # @return [self]
        #   array << '2001:1234::125'
        def push(addr)
          addr = Addr.new.from_human(addr) unless addr.is_a?(Addr)
          super
        end
      end
    end
  end
end
