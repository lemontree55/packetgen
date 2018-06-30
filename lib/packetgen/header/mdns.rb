# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header

    # Multicast DNS.
    #
    # See {DNS} for header format.
    # @author Sylvain Daubert
    class MDNS < DNS
      # Port number for mDNS over UDP
      UDP_PORT = 5353
      
      # Fixup IP header according to RFC 6762:
      # * set ethernet multicast address to +01:00:5E:00:00:FB+ (for IPv4)
      #   or +33:33:00:00:00:FB+ (for IPv6),
      # * set IPv4 address to 224.0.0.251 or IPv6 address to ff02::fb.
      # This method may be called as:
      #    # first way
      #    pkt.mdns.mdnsize
      #    # second way
      #    pkt.mdnsize
      def mdnsize
        iph = ip_header(self)
        case iph
        when IP
          iph.dst = '224.0.0.251'
          llh = ll_header(self)
          mac = case llh
                when Eth
                  llh[:dst]
                when Dot11
                  if llh.to_ds?
                    llh[:mac3]
                  else
                    llh[:mac1]
                  end
                end
          mac.from_human('01:00:5E:00:00:FB')
        when IPv6
          iph.dst = 'ff02::fb'
          llh = ll_header(self)
          mac = case llh
                when Eth
                  llh[:dst]
                when Dot11
                  if llh.to_ds?
                    llh[:mac3]
                  else
                    llh[:mac1]
                  end
                end
          mac.from_human('33:33:00:00:00:FB')
        end
      end
      
      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      def added_to_packet(packet)
        mdns_idx = packet.headers.size
        packet.instance_eval "def mdnsize() @headers[#{mdns_idx}].mdnsize; end"
      end
    end
    
    self.add_class MDNS
    UDP.bind_header MDNS, dport: MDNS::UDP_PORT, sport: MDNS::UDP_PORT
  end
end
