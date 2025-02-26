# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # Generic Routing Encapsulation (RFC 2784 and 2890)
    #                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |C| |K|S| Reserved0       | Ver |         Protocol Type         |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |      Checksum (optional)      |       Reserved1 (Optional)    |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                         Key (optional)                        |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                 Sequence Number (Optional)                    |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # A GRE header is composed of:
    # * A first 16-bit attribute containing given flags:
    #   * {#c} indicates if {#checksum} and {#reserved1} attributes are present.
    #   * {#k} indicates if {#key} attribute is present.
    #   * {#s} indicatesid {#sequence_number} attribute is present.
    #   * {#ver} 3-bit version number.
    # * {#protocol_type} (+BinStruct::Int16+).
    # * optional {#checksum} and {#reserved1} attribute (both +BinStruct::Int16+).
    # * optional {#key} attribute (+BinStruct::Int32+).
    # * optional {#sequence_number} attribute (+BinStruct::Int32+).
    # * and a {#body} (+BinStruct::String or {Headerable}).
    #
    # Current implementation supports tunneling {IP} and {IPv6} packets in GRE.
    # @author Sylvain Daubert
    # @author LemonTree55
    # @since 2.1.0
    class GRE < Base
      # IP protocol number for GRE
      IP_PROTOCOL = 47

      # @!attribute c
      #   Say if {#checksum} and {#reserved1} attributes are present
      #   @return [Boolean]
      # @!attribute k
      #   Say if {#key} attribute is present
      #   @return [Boolean]
      # @!attribute s
      #   Say if {#sequence_number} attribute is present
      #   @return [Boolean]
      # @!attribute reserved0
      #   @return [Integer]
      # @!attribute ver
      #   3-bit GRE protocol version.
      #   @return [Integer]
      define_bit_attr :u16, c: 1, r: 1, k: 1, s: 1, reserved0: 9, ver: 3

      # @!attribute protocol_type
      #   @return [Integer]
      define_attr :protocol_type, BinStruct::Int16
      # @!attribute checksum
      #   IP checksum over all 16-bit words in GRE header and its body. Present only if {#c} is set.
      #   @return [Integer]
      define_attr :checksum, BinStruct::Int16, default: 0, optional: lambda(&:c?)
      # @!attribute reserved1
      #   Reserved field, present only if {#c} is set.
      #   @return [Integer]
      define_attr :reserved1, BinStruct::Int16, default: 0, optional: lambda(&:c?)
      # @!attribute key
      #   32-bit integer used to identify an individual traffic flow within a tunnel.
      #   Present only if {#k} is set.
      #   @return [Integer]
      define_attr :key, BinStruct::Int32, optional: lambda(&:k?)
      # @!attribute sequence_number
      #   32-bit integer. Present only if {#s} is set.
      #   @return [Integer]
      define_attr :sequence_number, BinStruct::Int32, optional: lambda(&:s?)
      # @!attribute body
      #   @return [BinStruct::String,Headerable]
      define_attr :body, BinStruct::String

      alias seqnum sequence_number
      alias seqnum= sequence_number=

      def initialize(options={})
        opts = { r: false, reserved0: 0, version: 0 }.merge(options)
        super(opts)
      end

      # Compute checksum and set +checksum+ attribute.
      # @return [Integer]
      def calc_checksum
        sum = IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end
    end

    self.add_class GRE
    IP.bind GRE, protocol: GRE::IP_PROTOCOL
    IPv6.bind GRE, next: GRE::IP_PROTOCOL

    GRE.bind IP, protocol_type: IP::ETHERTYPE
    GRE.bind IPv6, protocol_type: IPv6::ETHERTYPE
  end
end
