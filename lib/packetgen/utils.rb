# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
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
    ARP_FILTER = 'arp src %<ipaddr>s and ether dst %<hwaddr>s'
    # @private
    MITM_FILTER = '((ip src %<target1>s and not ip dst %<local_ip>s) or ' \
                  '(ip src %<target2>s and not ip dst %<local_ip>s) or ' \
                  '(ip dst %<target1>s and not ip src %<local_ip>s) or ' \
                  '(ip dst %<target2>s and not ip src %<local_ip>s)) ' \
                  'and ether dst %<local_mac>s'

    # @private
    ARP_PATH = '/usr/sbin/arp'
    # @private
    IP_PATH = '/usr/bin/ip'
    # @private
    ARP_LINE_RE = /\((\d+\.\d+\.\d+\.\d+)\) at (([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})(?: \[ether\])? on (\w+)/
    # @private
    IP_LINE_RE = /^(\d+\.\d+\.\d+\.\d+) dev (\w+) lladdr (([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})/

    # Get local ARP cache
    # @return [Hash] key: IP address, value: array containing MAC address and
    #    interface name
    def self.arp_cache
      return self.cache_from_arp_command if File.exist?(ARP_PATH)
      return self.cache_from_ip_command if File.exist?(IP_PATH)

      {}
    end

    # @private
    def self.cache_from_arp_command(raw_cache=nil)
      raw_cache ||= `#{ARP_PATH} -an`

      cache = {}
      raw_cache.split("\n").each do |line|
        match = line.match(ARP_LINE_RE)
        cache[match[1]] = [match[2], match[4]] if match
      end

      cache
    end

    # @private
    def self.cache_from_ip_command(raw_cache=nil)
      raw_cache ||= `#{IP_PATH} neigh`

      cache = {}
      raw_cache.split("\n").each do |line|
        match = line.match(IP_LINE_RE)
        cache[match[1]] = [match[3], match[2]] if match
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
    #   request. Default to 1.
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

      capture = Capture.new(iface: iface, timeout: timeout, max: 1, filter: ARP_FILTER % { ipaddr: ipaddr, hwaddr: my_hwaddr })
      cap_thread = Thread.new { capture.start }

      sleep 0.1
      arp_pkt.to_w(iface)
      cap_thread.join

      return if capture.packets.empty?

      capture.packets.each do |pkt|
        break pkt.arp.sha.to_s if pkt.arp.spa.to_s == ipaddr
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize

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
    def self.mitm(target1, target2, options={}, &block)
      options = { iface: PacketGen.default_iface }.merge(options)

      spoofer = Utils::ARPSpoofer.new(options)
      spoofer.add target1, target2, options
      spoofer.add target2, target1, options

      cfg = Config.instance
      my_mac = cfg.hwaddr(options[:iface])
      capture = Capture.new(iface: options[:iface],
                            filter: MITM_FILTER % { target1: target1, target2: target2, local_ip: cfg.ipaddr(options[:iface]), local_mac: my_mac })

      spoofer.start_all
      mitm_core(capture, target1, target2, my_mac, &block)
      spoofer.stop_all
    end

    # @private
    def self.mitm_core(capture, target1, target2, my_mac)
      mac1 = arp(target1)
      mac2 = arp(target2)

      capture.start do |pkt|
        modified_pkt = yield pkt
        iph = modified_pkt.ip
        l2 = modified_pkt.is?('Dot11') ? modified_pkt.dot11 : modified_pkt.eth

        l2.src = my_mac
        l2.dst = if (iph.src == target1) || (iph.dst == target2)
                   mac2
                 else # (iph.src == target2) || (iph.dst == target1)
                   mac1
                 end
        modified_pkt.to_w(capture.iface)
      end
    end
  end
end
