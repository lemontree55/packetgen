# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'pcaprub'

module PacketGen
  # Wrapper around PCAPRUB
  # @author Sylvain Daubert
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
    # @return [PCAPRUB::Pcap]
    def self.open_iface(iface:, snaplen: DEFAULT_SNAPLEN, promisc: DEFAULT_PROMISC)
      PCAPRUB::Pcap.open_live(iface, snaplen, promisc, TIMEOUT)
    end

    # Capture packets from a network interface
    # @param [String] iface interface name
    # @param [Integer] snaplen
    # @param [Boolean] promisc
    # @param [String] filter BPF filter
    # @yieldparam [String] packet_data binary packet data
    # @return [void]
    def self.capture(iface:, snaplen: DEFAULT_SNAPLEN, promisc: DEFAULT_PROMISC, filter: nil)
      pcap = self.open_iface(iface: iface, snaplen: snaplen, promisc: promisc)
      pcap.setfilter filter unless filter.nil?
      pcap.each do |packet_data|
        yield packet_data
      end
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
  end
end
