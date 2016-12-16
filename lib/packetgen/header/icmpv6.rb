# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # ICMPv6 header class
    # @author Sylvain Daubert
    class ICMPv6 < ICMP

      # ICMPv6 internet protocol number
      IP_PROTOCOL = 58

      # Compute checksum and set +sum+ field
      # @return [Integer]
      def calc_sum
        sum = ip_header(self).pseudo_header_sum
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
        self[:sum].value = (sum == 0) ? 0xffff : sum
      end
    end

    IPv6.bind_header ICMPv6, next: ICMPv6::IP_PROTOCOL
  end
end
