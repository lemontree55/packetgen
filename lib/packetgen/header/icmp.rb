# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # ICMP header ({https://tools.ietf.org/html/rfc792 RFC 792})
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |     Type      |     Code      |          Checksum             |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # A ICMP header consists of:
    # * a {#type} field (+BinStruct::Int8+ type),
    # * a {#code} field (+BinStruct::Int8+ type),
    # * a {#checksum} field (+BinStruct::Int16+ type),
    # * and a {#body}.
    #
    # == Create a ICMP header
    #  # standalone
    #  icmp = PacketGen::Header::ICMP.new
    #  # in a packet
    #  pkt = PacketGen.gen('IP').add('ICMP')
    #  # access to ICMP header
    #  pkt.icmp     # => PacketGen::Header::ICMP
    #
    # == ICMP attributes
    #  icmp.code = 0
    #  icmp.type = 200
    #  icmp.checksum = 0x248a
    #  icmp.body.read 'this is a body'
    # @author Sylvain Daubert
    class ICMP < Base
      # ICMP internet protocol number
      IP_PROTOCOL = 1

      # @!attribute type
      #  8-bit ICMP type
      #  @return [Integer]
      define_attr :type, BinStruct::Int8
      # @!attribute code
      #  8-bit ICMP code
      #  @return [Integer]
      define_attr :code, BinStruct::Int8
      # @!attribute checksum
      #  16-bit ICMP checksum
      #  @return [Integer]
      define_attr :checksum, BinStruct::Int16
      # @!attribute body
      #  @return [BinStruct::String,Header::Base]
      define_attr :body, BinStruct::String

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end
    end

    self.add_class ICMP

    IP.bind ICMP, protocol: ICMP::IP_PROTOCOL
  end
end
