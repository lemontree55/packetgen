# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require_relative 'pcaprub_wrapper'

module PacketGen
  # Module to read PCAP files
  # @author Sylvain Daubert
  # @api private
  # @since 3.1.4
  module Pcap
    # Read a PCAP file
    # @param [String] filename
    # @return [Array<Packet>]
    # @author Kent Gruber
    def self.read(filename)
      packets = []
      PCAPRUBWrapper.read_pcap(filename: filename) do |packet|
        next unless (packet = PacketGen.parse(packet.to_s))

        packets << packet
      end
      packets
    end
  end
end
