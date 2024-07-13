# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # UDP header ({https://tools.ietf.org/html/rfc768 RFC 768})
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |          Source Port          |       Destination Port        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |             Length            |           Checksum            |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # A UDP header consists of:
    # * a source port field ({#sport}, {Types::Int16} type),
    # * a destination port field ({#dport}, +Int16+ type),
    # * a UDP length field ({#length}, +Int16+ type),
    # * a {#checksum} field (+Int16+ type),
    # * and a {#body}.
    #
    # == Create a UDP header
    #  # standalone
    #  udp = PacketGen::Header::UDP.new
    #  # in a packet
    #  pkt = PAcketGen.gen('IP').eadd('UDP')
    #  # access to IP header
    #  pkt.udp    # => PacketGen::Header::UDP
    #
    # == UDP attributes
    #  udp.sport = 65432
    #  udp.dport = 53
    #  udp.length = 43
    #  udp.checksum = 0xffff
    #  udp.body.read 'this is a UDP body'
    #
    # @author Sylvain Daubert
    class UDP < Base
      # IP protocol number for UDP
      IP_PROTOCOL = 17

      # @!attribute sport
      #  16-bit UDP source port
      #  @return [Integer]
      define_field :sport, Types::Int16
      # @!attribute dport
      #  16-bit UDP destination port
      #  @return [Integer]
      define_field :dport, Types::Int16
      # @!attribute length
      #  16-bit UDP length
      #  @return [Integer]
      define_field :length, Types::Int16, default: 8
      # @!attribute checksum
      #  16-bit UDP checksum
      #  @return [Integer]
      define_field :checksum, Types::Int16
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

      alias source_port sport
      alias source_port= sport=
      alias destination_port dport
      alias destination_port= dport=

      # Call {Base#initialize), and automagically compute +length+ if +:body+
      # option is set.
      def initialize(options={})
        super
        self.length += self[:body].sz if self[:body].sz.positive?
      end

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        ip = ip_header(self)
        sum = ip.pseudo_header_checksum
        sum += IP_PROTOCOL
        sum += self.sz
        sum += IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end

      # Compute length and set +length+ field
      # @return [Integer]
      def calc_length
        Base.calculate_and_set_length self
      end

      # Invert source and destination port numbers
      # @return [self]
      # @since 2.7.0
      def reply!
        self[:sport], self[:dport] = self[:dport], self[:sport]
        self
      end
    end

    self.add_class UDP

    IP.bind UDP, protocol: UDP::IP_PROTOCOL
    IPv6.bind UDP, next: UDP::IP_PROTOCOL
  end
end
