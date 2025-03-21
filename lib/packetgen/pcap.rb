# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.
require_relative 'pcaprub_wrapper'

module PacketGen
  # Module to read/write PCAP files
  # @api private
  # @since 3.1.4
  module Pcap
    # Read a PCAP file
    # @param [String] filename
    # @return [Array<Packet>]
    # @author Kent Gruber
    # @author LemonTree55
    def self.read(filename)
      packets = []
      PCAPRUBWrapper.read_pcap(filename: filename) do |raw_packet|
        packet = PacketGen.parse(raw_packet.to_s)
        next if packet.nil?

        packets << packet
      end
      packets
    end

    # Write binary packets to a PCAP file
    # @param [String] filename
    # @param [Array<String>] packets
    # @return [void]
    # @since 4.0.0
    # @author LemonTree55
    def self.write(filename, packets)
      PCAPRUBWrapper.pcap_write(filename, packets.map(&:to_s))
    end
  end
end
