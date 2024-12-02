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
    # @author Sylvain Daubert
    # @since 2.1.0
    class GRE < Base
      # IP protocol number for GRE
      IP_PROTOCOL = 47

      # @!attribute c
      #   @return [Boolean]
      # @!attribute k
      #   @return [Boolean]
      # @!attribute s
      #   @return [Boolean]
      # @!attribute reserved0
      #   @return [Integer]
      # @!attribute ver
      #   @return [Integer]
      define_bit_attr :u16, c: 1, r: 1, k: 1, s: 1, reserved0: 9, ver: 3

      # @!attribute protocol_type
      #   @return [Integer]
      define_attr :protocol_type, BinStruct::Int16
      # @!attribute checksum
      #   @return [Integer]
      define_attr :checksum, BinStruct::Int16, default: 0, optional: lambda(&:c?)
      # @!attribute reserved1
      #   @return [Integer]
      define_attr :reserved1, BinStruct::Int16, default: 0, optional: lambda(&:c?)
      # @!attribute key
      #   @return [Integer]
      define_attr :key, BinStruct::Int32, optional: lambda(&:k?)
      # @!attribute sequence_number
      #   @return [Integer]
      define_attr :sequence_number, BinStruct::Int32, optional: lambda(&:s?)
      # @!attribute body
      #  @return [BinStruct::String,Header::Base]
      define_attr :body, BinStruct::String

      alias seqnum sequence_number
      alias seqnum= sequence_number=

      def initialize(options={})
        opts = { r: false, reserved0: 0, version: 0 }.merge(options)
        super(opts)
      end

      # Compute checksum and set +checksum+ field
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
