# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

require_relative 'config'
require_relative 'utils/arp_spoofer'

module PacketGen
  # Collection of some network utilities.
  #
  # This module is not enabled by default. You need to:
  #  require 'packetgen/utils'
  # @author Sylvain Daubert
  # @since 2.1.3
  module Utils
    # Get local ARP cache
    # @return [Hash] key: IP address, value: array containing MAC address and
    #    interface name
    def self.arp_cache
      raw_cache = `/usr/sbin/arp -an`

      cache = {}
      raw_cache.split(/\n/).each do |line|
        match = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at (([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})(?: \[ether\])? on (\w+)/)
        cache[match[1]] = [match[2], match[4]] if match
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
        return local_cache[ipaddr].first if local_cache.key? ipaddr
      end

      iface = options[:iface] || PacketGen.default_iface
      timeout = options[:timeout] || 1
      my_hwaddr = Config.instance.hwaddr(iface)
      arp_pkt = Packet.gen('Eth', dst: 'ff:ff:ff:ff:ff:ff', src: my_hwaddr)
      arp_pkt.add('ARP', sha: Config.instance.hwaddr, spa: Config.instance.ipaddr,
                         tpa: ipaddr)

      capture = Capture.new(iface: iface, timeout: timeout, max: 1,
                            filter: "arp src #{ipaddr} and ether dst #{my_hwaddr}")
      cap_thread = Thread.new do
        capture.start
      end

      arp_pkt.to_w(iface)
      cap_thread.join

      return if capture.packets.empty?
      capture.packets.each do |pkt|
        break pkt.arp.sha.to_s if pkt.arp.spa.to_s == ipaddr
      end
    end

    # Do ARP spoofing on given IP address. Call to this method blocks.
    # @note This method is provided for test purpose.
    # For more control, see {ARPSpoofer} class.
    # @param [String] target_ip target IP address
    # @param [String] spoofed_ip IP address to spoof
    # @param [Hash] options
    # @option options [String] :mac MAC address used to poison target
    #   ARP cache. Default to local MAC address.
    # @option options [Integer,nil] :for_seconds number of seconds to do ARP spoofing.
    #   If not defined, spoof forever.
    # @option options [Float,Integer] :interval number of seconds between 2
    #   ARP packets (default: 1.0).
    # @option options [String] :iface interface to use. Default to
    #   {PacketGen.default_iface}
    # @return [void]
    def self.arp_spoof(target_ip, spoofed_ip, options={})
      interval = options[:interval] || 1.0
      as = ARPSpoofer.new(timeout: options[:for_seconds], interval: interval,
                          iface: options[:iface])
      as.start(target_ip, spoofed_ip, mac: options[:mac])
      as.wait
    end

    # Man in the middle attack. Capture all packets between two peers on
    # same local network.
    # @note This method is provided for test purpose.
    # @param [String] target1 IP address of first peer to attack
    # @param [String] target2 IP address of second peer to attack
    # @param [Hash] options
    # @option options [Float,Integer] :interval number of seconds between 2
    #   ARP packets (default: 1.0).
    # @option options [String] :iface interface to use. Default to
    #   {PacketGen.default_iface}
    # @return [void]
    # @yieldparam [Packet] pkt captured packets between target1 and target2
    # @yieldreturn [Packet] packet to send to target1 or 2. This may be
    #   modified received packet
    # @example Change ID in packets
    #   PacketGen::Utils.mitm('192.168.0.1', '192.168.0.45') do |pkt|
    #     if pkt.ip.src == '192.168.0.1'
    #       # 192.168.0.1 -> 192.168.0.45
    #       pkt.ip.id = 1
    #     else
    #       # 192.168.0.45 -> 192.168.0.1
    #       pkt.ip.id = 2
    #     end
    #     pkt
    #   end
    # @since 2.2.0
    def self.mitm(target1, target2, options={})
      options = { iface: PacketGen.default_iface }.merge(options)

      spoofer = Utils::ARPSpoofer.new(options)
      spoofer.add target1, target2, options
      spoofer.add target2, target1, options

      my_mac = Config.instance.hwaddr(options[:iface])
      my_ip = Config.instance.ipaddr(options[:iface])
      capture = Capture.new(iface: options[:iface],
                            filter: "((ip src #{target1} and not ip dst #{my_ip}) or" \
                                    " (ip src #{target2} and not ip dst #{my_ip}) or" \
                                    " (ip dst #{target1} and not ip src #{my_ip}) or" \
                                    " (ip dst #{target2} and not ip src #{my_ip}))" \
                                    " and ether dst #{my_mac}")

      spoofer.start_all
      capture.start do |pkt|
        modified_pkt = yield pkt
        modified_pkt.ip.to_w(options[:iface])
      end
    end
  end
end
