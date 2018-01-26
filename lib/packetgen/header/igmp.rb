# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
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
    # * a {#type} field ({Types::Int8Enum} type),
    # * a {#max_resp_time} field ({Types::Int8} type),
    # * a {#checksum} field ({Types::Int16} type),
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
    class IGMP < Base

      # IGMP internet protocol number
      IP_PROTOCOL = 2
      
      # Known types
      TYPES = {
        'MembershipQuery'    => 0x11,
        'MembershipReportv1' => 0x12,
        'MembershipReportv2' => 0x16,
        'LeaveGroup'         => 0x17,
      }

      # @!attribute type
      #  8-bit IGMP Type
      #  @return [Integer]
      define_field :type, Types::Int8Enum, enum: TYPES
      # @!attribute max_resp_time
      #  8-bit IGMP Max Response Time
      #  @return [Integer]
      define_field :max_resp_time, Types::Int8
      # @!attribute checksum
      #  16-bit IGMP Checksum
      #  @return [Integer]
      define_field :checksum, Types::Int16
      # @!attribute group_addr
      #  IP Group address
      #  @return [IP::Addr]
      define_field :group_addr, IP::Addr, default: '0.0.0.0'
      # @!attribute body
      #  @return [String,Base]
      define_field :body, Types::String

      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      def added_to_packet(packet)
        igmp_idx = packet.headers.size
        packet.instance_eval "def igmpize() @headers[#{igmp_idx}].igmpize; end"
      end

      # Get human readbale type
      # @return [String]
      def human_type
        self[:type].to_human
      end

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = (type << 8) | max_resp_time

        payload = self[:group_addr].to_s + body.to_s
        payload << "\x00" unless payload.size % 2 == 0
        payload.unpack('n*').each { |x| sum += x; }

        while sum > 0xffff do
          sum = (sum & 0xffff) + (sum >> 16)
        end
        sum = ~sum & 0xffff
        self[:checksum].value = (sum == 0) ? 0xffff : sum
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
    IP.bind_header IGMP, op: :and, protocol: IGMP::IP_PROTOCOL, frag: 0, ttl: 1,
                   tos: ->(v) { v.nil? ? 0 : v != 0xc0 }
  end
end
