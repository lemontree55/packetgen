# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # ICMPv6 header ({https://tools.ietf.org/html/rfc4443 RFC 4443})
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |     Type      |     Code      |          Checksum             |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # A ICMPv6 header consists of:
    # * a +type+ field (+BinStruct::Int8+ type),
    # * a +code+ field (+BinStruct::Int8+ type),
    # * a +checksum+ field (+BinStruct::Int16+ type),
    # * and a +body+.
    #
    # == Create a ICMPv6 header
    #  # standalone
    #  icmpv6 = PacketGen::Header::ICMPv6.new
    #  # in a packet
    #  pkt = PacketGen.gen('IPv6').add('ICMPv6')
    #  # access to ICMPv6 header
    #  pkt.icmpv6     # => PacketGen::Header::ICMPv6
    #
    # == ICMPv6 attributes
    #  icmpv6.code = 0
    #  icmpv6.type = 200
    #  icmpv6.checksum = 0x248a
    #  icmpv6.body.read 'this is a body'
    # @author Sylvain Daubert
    class ICMPv6 < ICMP
      # ICMPv6 internet protocol number
      IP_PROTOCOL = 58

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = ip_header(self).pseudo_header_checksum
        sum += self.sz
        sum += IP_PROTOCOL
        sum += IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end
    end

    self.add_class ICMPv6
    IPv6.bind ICMPv6, next: ICMPv6::IP_PROTOCOL
  end
end
