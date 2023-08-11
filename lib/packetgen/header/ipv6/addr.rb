# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

require 'ipaddr'

module PacketGen
  module Header
    class IPv6
      # IPv6 address, as a group of 8 2-byte words
      # @author Sylvain Daubert
      class Addr < Types::Fields
        include Types::Fieldable

        # @!attribute a1
        #  1st 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a1, Types::Int16
        # @!attribute a2
        #  2nd 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a2, Types::Int16
        # @!attribute a3
        #  3rd 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a3, Types::Int16
        # @!attribute a4
        #  4th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a4, Types::Int16
        # @!attribute a5
        #  5th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a5, Types::Int16
        # @!attribute a6
        #  6th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a6, Types::Int16
        # @!attribute a7
        #  7th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a7, Types::Int16
        # @!attribute a8
        #  8th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a8, Types::Int16

        # rubocop:disable Metrics/AbcSize

        # Read a colon-delimited address
        # @param [String] str
        # @return [self]
        def from_human(str)
          return self if str.nil?

          addr = IPAddr.new(str)
          raise ArgumentError, 'string is not a IPv6 address' unless addr.ipv6?

          addri = addr.to_i
          self.a1 = addri >> 112
          self.a2 = addri >> 96 & 0xffff
          self.a3 = addri >> 80 & 0xffff
          self.a4 = addri >> 64 & 0xffff
          self.a5 = addri >> 48 & 0xffff
          self.a6 = addri >> 32 & 0xffff
          self.a7 = addri >> 16 & 0xffff
          self.a8 = addri & 0xffff
          self
        end
        # rubocop:enable Metrics/AbcSize

        # Addr6 in human readable form (colon-delimited hex string)
        # @return [String]
        def to_human
          IPAddr.new(to_a.map { |a| a.to_i.to_s(16) }.join(':')).to_s
        end

        # Return an array of address 16-bit words
        # @return [Array<Integer>]
        def to_a
          @fields.values
        end

        # Return true if this address is a multicast one
        # @return [Boolean]
        def mcast?
          self.a1 & 0xff00 == 0xff00
        end

        def ==(other)
          other.is_a?(self.class) &&
            fields.all? { |attr| self[attr].value == other[attr].value }
        end
      end

      # Class to handle series of IPv6 addresses
      # @author Sylvain Daubert
      class ArrayOfAddr < Types::Array
        set_of IPv6::Addr

        # Push a IPv6 address to the array
        # @param [String,Addr] addr
        # @return [self]
        #   array << '2001:1234::125'
        def push(addr)
          addr = Addr.new.from_human(addr) unless addr.is_a?(Addr)
          super(addr)
        end
      end
    end
  end
end
