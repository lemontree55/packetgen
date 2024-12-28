# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.
require 'pcaprub'

module PacketGen
  # Wrapper around PCAPRUB
  # @author Sylvain Daubert
  # @author LemonTree55
  # @api private
  # @since 3.1.4
  module PCAPRUBWrapper
    # timeout for PCAPRUB
    TIMEOUT = 1
    # Default snaplen to use
    DEFAULT_SNAPLEN = 0xffff
    # Default promisc value to use
    DEFAULT_PROMISC = false

    # Open an interface for capturing
    # @param [String] iface interface name
    # @param [Integer] snaplen
    # @param [Boolean] promisc
    # @param [Boolean] monitor
    # @return [PCAPRUB::Pcap]
    # @author Sylvain Daubert
    # @author optix2000 - add support for setting monitor mode
    # @since 3.1.5 add monitor argument
    def self.open_iface(iface:, snaplen: DEFAULT_SNAPLEN, promisc: DEFAULT_PROMISC, monitor: nil)
      pcap = PCAPRUB::Pcap.create(iface)
      pcap.setsnaplen(snaplen)
      pcap.setpromisc(promisc)
      pcap.settimeout(TIMEOUT)
      # Monitor MUST be set before pcap is activated
      pcap.setmonitor(monitor) unless monitor.nil?
      pcap.activate
      pcap
    end

    # Capture packets from a network interface
    # @param [String] iface interface name
    # @param [Integer] snaplen
    # @param [Boolean] promisc
    # @param [String] filter BPF filter
    # @param [Boolean] monitor
    # @yieldparam [String] packet_data packet data
    # @return [void]
    # @author Sylvain Daubert
    # @author optix2000 - add support for setting monitor mode
    # @since 3.1.5 add monitor argument
    def self.capture(iface:, snaplen: DEFAULT_SNAPLEN, promisc: DEFAULT_PROMISC, filter: nil, monitor: nil, &block)
      pcap = self.open_iface(iface: iface, snaplen: snaplen, promisc: promisc, monitor: monitor)
      pcap.setfilter filter unless filter.nil?
      pcap.each_packet(&block)
    end

    # Inject given data onto wire
    # @param [String] iface interface name
    # @param [String] data to inject
    # @return [void]
    def self.inject(iface:, data:)
      pcap = self.open_iface(iface: iface)
      pcap.inject(data)
      pcap.close
    end

    # Read a PCAP file
    # @param [String] filename
    # @yieldparam [String] data binary packet data
    # @return [void]
    # @author Kent Gruber
    def self.read_pcap(filename:, &block)
      PCAPRUB::Pcap.open_offline(filename).each_packet(&block)
    end

    # Write binary packets to a PCAP file
    # @param [String] filename
    # @param [Array<String>] packets
    # @return [void]
    # @since 4.0.0
    # @author LemonTree55
    def self.write_pcap(filename:, packets:)
      PCAPRUB::Pcap.dump_open(filename) do |pcap|
        packets.each do |packet|
          pcap.dump(packet)
        end
      end
    end
  end
end
