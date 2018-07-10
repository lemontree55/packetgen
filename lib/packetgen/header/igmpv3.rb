# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header

    # This class supports IGMPv3 (RFC3376).
    #
    # From RFC 3376, a IGMP header has the following format:
    #   0                   1                   2                   3
    #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |      Type     | Max Resp Code |           Checksum            |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # A IGMP header consists of:
    # * a {#type} field ({Types::Int8Enum} type),
    # * a {#max_resp_time} field ({Types::Int8} type),
    # * a {#checksum} field ({Types::Int16} type),
    # * and a {#body}, containing more fields (see below).
    #
    # A IGMPv3 header may have additionnal fields. These fields are handled by
    # additional headers (see {IGMPv3::MQ}).
    #
    # == Create a IGMPv3 header
    #  # standalone
    #  igmp = PacketGen::Header::IGMPv3.new
    #  # in a packet
    #  pkt = PacketGen.gen('IP').add('IGMPv3')
    #  # access to IGMPv3 header
    #  pkt.igmp    # => PacketGen::Header::IGMPv3
    #
    # == IGMPv3 attributes
    #  igmp.type = 'MembershipQuery'   # or 0x11
    #  igmp.max_resp_time = 20
    #  igmp.checksum = 0x248a
    #
    # == IGMPv3 specifics
    # === Max Resp Code
    # {#max_resp_code} field of IGMPv3 packets is encoded differently than
    # previous versions. This encoding permits to set value up to 31743 (instead
    # of 255 for IGMPv2).
    #
    # This encoding is handled by {#max_resp_code} accessors:
    #   igmp.max_resp_code = 10000
    #   igmp.max_resp_code   #=> 9728  error due to encoding as a floating point value
    #
    # === IGMPv3 Membership Query
    # With IGMPv3, a Membership Query packet has more fields than with IGMPv2. To
    # handle those fields, an additional header should be used:
    #   pkt = PacketGen.gen('IP').add('IGMPv3', type: 'MembershipQuery').add('IGMPv3::MQ')
    #   pkt.igmpv3      #=> PacketGen::Header::IGMPv3
    #   pkt.igmpv3_mq   #=> PacketGen::Header::IGMPv3::MQ
    #
    # === IGMPv3 Membership Report
    # With IGMPv3, a Membership Report packet has more fields than with IGMPv2. To
    # handle those fields, an additional header should be used:
    #   pkt =  PacketGen.gen('IP').add('IGMPv3', type: 'MembershipQuery').add('IGMPv3::MR')
    #   pkt.igmpv3      #=> PacketGen::Header::IGMPv3
    #   pkt.igmpv3_mr  #=> PacketGen::Header::IGMPv3::MR
    # @author Sylvain Daubert
    # @since 2.4.0
    class IGMPv3 < IGMP

      # Known types
      TYPES = {
        'MembershipQuery'  => 0x11,
        'MembershipReport' => 0x22,
      }

      delete_field :group_addr
      #undef group_addr
      #undef group_addr=

      # Encode value for IGMPv3 Max Resp Code and QQIC.
      # Value may be encoded as a float, so some error may occur.
      # See RFC 3376 §4.1.1 and §4.1.7.
      # @param [Integer] value
      # @return [Integer]
      def self.encode(value)
        if value < 128
          value
        elsif value > 31743
          255
        else
          exp = 0
          value >>= 3
          while value > 31 do
            exp += 1
            value >>= 1
          end
          0x80 | (exp << 4) | (value & 0xf)
        end
      end

      # Decode value for IGMPv3 Max Resp Code and QQIC.
      # See RFC 3376 §4.1.1 and §4.1.7.
      # @param [Integer] value
      # @return [Integer]
      def self.decode(value)
        if value < 128
          value
        else
          mant = value & 0xf
          exp = (value >> 4) & 0x7
          (0x10 | mant) << (exp + 3)
        end
      end

      # Getter for +max_resp_time+ for IGMPv3 packets. Use {.decode}.
      # @return [Integer]
      def max_resp_time
        IGMPv3.decode(self[:max_resp_time].value || self[:max_resp_time].default)
      end
      alias max_resp_code max_resp_time

      # Setter for +max_resp_time+ for IGMPv3 packets. Use {.encode}.
      # @param [Integer] value
      # @return [Integer]
      def max_resp_time=(value)
        self[:max_resp_time].value = IGMPv3.encode(value)
      end
      alias max_resp_code= max_resp_time=

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end
    end

    self.add_class IGMPv3
    IP.bind_header IGMPv3, op: :and, protocol: IGMPv3::IP_PROTOCOL, frag: 0, ttl: 1,
                   tos: 0xc0
  end
end

require_relative 'igmpv3/mq'
require_relative 'igmpv3/mr'
