# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require 'stringio'

module PacketGen
  # Module to handle PCAP-NG file format.
  # See http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii
  #
  # See {PcapNG::File} to handle Pcap-NG files.
  # @author Sylvain Daubert
  module PcapNG
    # Section Header Block type number
    SHB_TYPE = BinStruct::Int32.new(value: 0x0A0D0D0A, endian: :little).freeze
    # Interface Description Block type number
    IDB_TYPE = BinStruct::Int32.new(value: 1, endian: :little).freeze
    # Simple Packet Block type number
    SPB_TYPE = BinStruct::Int32.new(value: 3, endian: :little).freeze
    # Enhanced Packet Block type number
    EPB_TYPE = BinStruct::Int32.new(value: 6, endian: :little).freeze

    # IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up)
    LINKTYPE_ETHERNET = 1
    # Raw IP; the packet begins with an IPv4 or IPv6 header, with the "version"
    # field of the header indicating whether it's an IPv4 or IPv6 header.
    LINKTYPE_RAW = 101
    # IEEE 802.11 wireless LAN
    LINKTYPE_IEEE802_11 = 105
    # RadioTap link layer informations + IEEE 802.11 wireless LAN
    LINKTYPE_IEEE802_11_RADIOTAP = 127
    # Per-Packet Information information, as specified by the Per-Packet Information
    # Header Specification, followed by a packet with the LINKTYPE_ value specified
    # by the +pph_dlt+ field of that header.
    LINKTYPE_PPI = 192
    # Raw IPv4; the packet begins with an IPv4 header.
    LINKTYPE_IPV4 = 228
    # Raw IPv6; the packet begins with an IPv6 header.
    LINKTYPE_IPV6 = 229

    # Base error class for PcapNG
    class Error < PacketGen::Error; end

    # Invalid PcapNG file error
    class InvalidFileError < Error; end
  end
end

require_relative 'pcapng/block'
require_relative 'pcapng/unknown_block'
require_relative 'pcapng/shb'
require_relative 'pcapng/idb'
require_relative 'pcapng/epb'
require_relative 'pcapng/spb'
require_relative 'pcapng/file'
