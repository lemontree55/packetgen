# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # This class supports IGMPv2 (RFC 2236).
    #
    # From RFC 2236, a IGMP header has the following format:
    #   0                   1                   2                   3
    #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |      Type     | Max Resp Time |           Checksum            |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                         Group Address                         |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # A IGMP header consists of:
    # * a {#type} field ({BinStruct::Int8Enum} type),
    # * a {#max_resp_time} field ({BinStruct::Int8} type),
    # * a {#checksum} field ({BinStruct::Int16} type),
    # * a {#group_addr} field ({Header::IP::Addr} type),
    # * and a {#body} (unused for IGMPv2).
    #
    # == Create a IGMP header
    #  # standalone
    #  igmp = PacketGen::Header::IGMP.new
    #  # in a packet
    #  pkt = PacketGen.gen('IP').add('IGMP')
    #  # access to IGMP header
    #  pkt.igmp    # => PacketGen::Header::IGMP
    #
    # == IGMP attributes
    #  icmp.type = 'MembershipQuery'   # or 0x11
    #  icmp.max_resp_time = 20
    #  icmp.checksum = 0x248a
    #  icmp.group_addr = '224.0.0.1'
    # @author Sylvain Daubert
    # @since 2.4.0
    class IGMP < Base
      # IGMP internet protocol number
      IP_PROTOCOL = 2

      # Known types
      TYPES = {
        'MembershipQuery' => 0x11,
        'MembershipReportv1' => 0x12,
        'MembershipReportv2' => 0x16,
        'LeaveGroup' => 0x17,
      }.freeze

      # @!attribute type
      #  8-bit IGMP Type
      #  @return [Integer]
      define_attr :type, BinStruct::Int8Enum, enum: TYPES
      # @!attribute max_resp_time
      #  8-bit IGMP Max Response Time
      #  @return [Integer]
      define_attr :max_resp_time, BinStruct::Int8
      # @!attribute checksum
      #  16-bit IGMP Checksum
      #  @return [Integer]
      define_attr :checksum, BinStruct::Int16
      # @!attribute group_addr
      #  IP Group address
      #  @return [IP::Addr]
      define_attr :group_addr, IP::Addr, default: '0.0.0.0'
      # @!attribute body
      #  @return [String,Base]
      define_attr :body, BinStruct::String

      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      def added_to_packet(packet)
        igmp_idx = packet.headers.size
        packet.instance_eval "def igmpize() @headers[#{igmp_idx}].igmpize; end" # def igmpize() @headers[2].igmpize; end
      end

      # Get human readbale type
      # @return [String]
      def human_type
        self[:type].to_human
      end

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end

      # Fixup IP header according to RFC 2236:
      # * set TTL to 1,
      # * add Router Alert option,
      # * recalculate checksum and length.
      # This method may be called as:
      #    # first method
      #    pkt.igmp.igmpize
      #    # second method
      #    pkt.igmpize
      # @return [void]
      def igmpize
        iph = ip_header(self)
        iph.ttl = 1
        iph.options << IP::RA.new
        packet.calc
      end
    end

    self.add_class IGMP
    IP.bind IGMP, protocol: IGMP::IP_PROTOCOL, frag: 0, ttl: 1,
                  tos: ->(v) { v.nil? ? 0 : v != 0xc0 }
  end
end
