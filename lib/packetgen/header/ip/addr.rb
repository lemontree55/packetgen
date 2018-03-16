# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class IP

      # IP address, as a group of 4 bytes
      # @author Sylvain Daubert
      class Addr < Types::Fields
        # @!attribute a1
        #  @return [Integer] IP address first byte 
        define_field :a1, Types::Int8
        # @!attribute a2
        #  @return [Integer] IP address seconf byte 
        define_field :a2, Types::Int8
        # @!attribute a3
        #  @return [Integer] IP address third byte 
        define_field :a3, Types::Int8
        # @!attribute a4
        #  @return [Integer] IP address fourth byte 
        define_field :a4, Types::Int8

        IPV4_ADDR_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

        # Read a dotted address
        # @param [String] str
        # @return [self]
        def from_human(str)
          return self if str.nil?
          m = str.match(IPV4_ADDR_REGEX)
          if m
            self[:a1].read m[1].to_i
            self[:a2].read m[2].to_i
            self[:a3].read m[3].to_i
            self[:a4].read m[4].to_i
          end
          self
        end

        # Addr in human readable form (dotted format)
        # @return [String]
        def to_human
          fields.map { |f| "#{self[f].to_i}" }.join('.')
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
      end
    end
  end
end
