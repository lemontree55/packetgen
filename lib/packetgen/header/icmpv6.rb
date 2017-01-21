# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # A ICMPv6 header consists of:
    # * a +type+ field ({Types::Int8} type),
    # * a +code+ field ({Types::Int8} type),
    # * a +checksum+ field ({Types::Int16} type),
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
        sum +=(type << 8) | code

        payload = body.to_s
        payload << "\x00" unless payload.size % 2 == 0
        payload.unpack('n*').each { |x| sum += x }

        while sum > 0xffff do
          sum = (sum & 0xffff) + (sum >> 16)
        end
        sum = ~sum & 0xffff
        self[:checksum].value = (sum == 0) ? 0xffff : sum
      end
    end

    self.add_class ICMPv6

    IPv6.bind_header ICMPv6, next: ICMPv6::IP_PROTOCOL
  end
end
