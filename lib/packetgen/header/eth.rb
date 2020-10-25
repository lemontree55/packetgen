# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    # An Ethernet header consists of:
    # * a destination MAC address ({MacAddr}),
    # * a source MAC address (MacAddr),
    # * a {#ethertype} ({Types::Int16}),
    # * and a body (a {Types::String} or another Header class).
    #
    # == Create a Ethernet header
    #  # standalone
    #  eth = PacketGen::Header::Eth.new
    #  # in a packet
    #  pkt = PacketGen.gen('Eth')
    #  # access to Ethernet header
    #  pkt.eth   # => PacketGen::Header::Eth
    #
    # == Ethernet attributes
    #  eth.dst = "00:01:02:03:04:05"
    #  eth.src        # => "00:01:01:01:01:01"
    #  eth[:src]      # => PacketGen::Header::Eth::MacAddr
    #  eth.ethertype  # => 16-bit Integer
    #  eth.body = "This is a body"
    #
    # @author Sylvain Daubert
    class Eth < Base
      # Ethernet MAC address, as a group of 6 bytes
      # @author Sylvain Daubert
      class MacAddr < Types::Fields
        include Types::Fieldable

        # @!attribute a0
        #  @return [Integer] first byte from MacAddr
        define_field :a0, Types::Int8
        # @!attribute a1
        #  @return [Integer] second byte from MacAddr
        define_field :a1, Types::Int8
        # @!attribute a2
        #  @return [Integer] third byte from MacAddr
        define_field :a2, Types::Int8
        # @!attribute a3
        #  @return [Integer] fourth byte from MacAddr
        define_field :a3, Types::Int8
        # @!attribute a4
        #  @return [Integer] fifth byte from MacAddr
        define_field :a4, Types::Int8
        # @!attribute a5
        #  @return [Integer] sixth byte from MacAddr
        define_field :a5, Types::Int8

        # Read a human-readable string to populate +MacAddr+
        # @param [String] str
        # @return [self]
        def from_human(str)
          return self if str.nil?

          bytes = str.split(/:/)
          raise ArgumentError, 'not a MAC address' unless bytes.size == 6

          6.times do |i|
            self["a#{i}".to_sym].read(bytes[i].to_i(16))
          end
          self
        end

        # +MacAddr+ in human readable form (colon format)
        # @return [String]
        def to_human
          fields.map { |m| '%02x' % self[m] }.join(':')
        end

        def ==(other)
          other.is_a?(self.class) &&
            fields.all? { |attr| self[attr].value == other[attr].value }
        end
      end

      # @!attribute dst
      #  @return [MacAddr] Destination MAC address
      define_field :dst, MacAddr, default: '00:00:00:00:00:00'
      # @!attribute src
      #  @return [MacAddr] Source MAC address
      define_field :src, MacAddr, default: '00:00:00:00:00:00'
      # @!attribute ethertype
      #  @return [Integer] 16-bit integer to determine payload type
      define_field :ethertype, Types::Int16, default: 0
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

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
