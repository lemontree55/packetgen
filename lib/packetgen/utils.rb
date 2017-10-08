# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require_relative 'config'

module PacketGen

  # Collection of some network utilities.
  # @author Sylvain Daubert
  module Utils

    # @private
    @config = Config.new

    # Get local ARP cache
    # @return [Hash] key: IP address, value: array containing MAC address and
    #    interface name
    def self.arp_cache
      raw_cache = %x(/usr/sbin/arp -an)

      cache = {}
      raw_cache.split(/\n/).each do |line|
        match = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at (([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})(?: \[ether\])? on (\w+)/)
        if match
          cache[match[1]] = [match[2], match[4]]
        end
      end
      
      cache
    end
    
    # Get MAC address from an IP address, or nil if this IP address is unknown
    # on local network.
    # @param [String] ipaddr dotted-octet IP address
    # @param [Hash] options
    # @option options [String] :iface interface name. Default to 
    #   {PacketGen.default_iface}
    # @option options [Boolean] :no_cache if +true+, do not query local ARP
    #   cache and always send an ARP request on wire. Default to +false+
    # @option options [Integer] :timeout timeout in seconds before stopping
    #   request. Default to 2.
    # @return [String,nil]
    def self.arp(ipaddr, options={})
      unless options[:no_cache]
        local_cache = self.arp_cache
        return local_cache[ipaddr].first if local_cache.has_key? ipaddr
      end

      iface = options[:iface] || PacketGen.default_iface
      timeout = options[:timeout] || 2
      
      arp_pkt = Packet.gen('Eth', dst: 'ff:ff:ff:ff:ff:ff', src: @config.hwaddr)
      arp_pkt.add('ARP', sha: @config.hwaddr, tpa: ipaddr)
      
      capture = Capture.new(iface: iface, timeout: timeout, max: 3,
                            filter: "arp src #{ipaddr} and ether dst #{@config.hwaddr}")
      cap_thread = Thread.new do
        capture.start
      end

      arp_pkt.to_w(iface)
      cap_thread.join
      
      if capture.packets.size > 0
        capture.packets.each do |pkt|
          if pkt.arp.spa.to_s == ipaddr
            break pkt.arp.sha.to_s
          end
        end
      else
        nil
      end
    end
  end
end
