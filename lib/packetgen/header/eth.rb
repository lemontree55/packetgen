# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # An Ethernet header consists of:
    # * a destination MAC address ({MacAddr}),
    # * a source MAC address ({MacAddr}),
    # * a {#ethertype} (+BinStruct::Int16+),
    # * and a body (a +BinStruct::String+ or another {Headerable} class).
    #
    # @example Create a Ethernet header
    #  # standalone
    #  eth = PacketGen::Header::Eth.new
    #  # in a packet
    #  pkt = PacketGen.gen('Eth')
    #  # access to Ethernet header
    #  pkt.eth.class   # => PacketGen::Header::Eth
    #
    # @example Access to Ethernet attributes
    #  eth = PacketGen::Header::Eth.new(src: '00:01:01:01:01:01', ethertype: 0x1234)
    #  # Set destination MAC address
    #  eth.dst = "00:01:02:03:04:05"
    #  # Access source MAC address, human-redable
    #  eth.src            # => "00:01:01:01:01:01"
    #  # Access to MacAddr object
    #  eth[:src].class    # => PacketGen::Header::Eth::MacAddr
    #  eth.ethertype      # => 0x1234
    #  # Set Ethernet body
    #  eth.body = "This is a body"
    #
    # @author Sylvain Daubert
    # @author LemonTree55
    class Eth < Base
      # Ethernet MAC address, as a group of 6 bytes
      # @author Sylvain Daubert
      class MacAddr < BinStruct::Struct
        include BinStruct::Structable

        # @!attribute a0
        #  @return [Integer] first byte from MacAddr
        define_attr :a0, BinStruct::Int8
        # @!attribute a1
        #  @return [Integer] second byte from MacAddr
        define_attr :a1, BinStruct::Int8
        # @!attribute a2
        #  @return [Integer] third byte from MacAddr
        define_attr :a2, BinStruct::Int8
        # @!attribute a3
        #  @return [Integer] fourth byte from MacAddr
        define_attr :a3, BinStruct::Int8
        # @!attribute a4
        #  @return [Integer] fifth byte from MacAddr
        define_attr :a4, BinStruct::Int8
        # @!attribute a5
        #  @return [Integer] sixth byte from MacAddr
        define_attr :a5, BinStruct::Int8

        # Read a human-readable string to populate +MacAddr+
        # @param [String] str
        # @return [self]
        # @example
        #   mac = PacketGen::Header::Eth::MacAddr.new
        #   mac.from_human('01:02:03:04:05:06')
        #   mac.a5  # => 6
        def from_human(str)
          return self if str.nil?

          bytes = str.split(':')
          raise ArgumentError, 'not a MAC address' unless bytes.size == 6

          6.times do |i|
            self[:"a#{i}"].from_human(bytes[i].to_i(16))
          end
          self
        end

        # +MacAddr+ in human readable form (colon format)
        # @return [String]
        def to_human
          attributes.map { |m| '%02x' % self[m] }.join(':')
        end

        # Equality check. +true+ only if +other+ is a MacAddr, and each address byte is the same.
        # @return [Boolean]
        def ==(other)
          other.is_a?(self.class) &&
            attributes.all? { |attr| self[attr].value == other[attr].value }
        end
      end

      # @!attribute dst
      #  Destination MAC address
      #  @return [::String]
      define_attr :dst, MacAddr, default: '00:00:00:00:00:00'
      # @!attribute src
      #  Source MAC address
      #  @return [::String]
      define_attr :src, MacAddr, default: '00:00:00:00:00:00'
      # @!attribute ethertype
      #  @return [Integer] 16-bit integer to determine payload type
      define_attr :ethertype, BinStruct::Int16, default: 0
      # @!attribute body
      #  @return [BinStruct::String,Headerable]
      define_attr :body, BinStruct::String

      # send Eth packet on wire.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface)
        Inject.inject(iface: iface, data: self)
      end

      # Invert destination and source addresses
      # @return [self]
      # @since 2.7.0
      def reply!
        self[:src], self[:dst] = self[:dst], self[:src]
        self
      end
    end
    self.add_class Eth
  end
end
