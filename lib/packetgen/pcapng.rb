# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'stringio'

module PacketGen

  # Module to handle PCAP-NG file format.
  # See http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii
  module PcapNG

    # Section Header Block type number
    SHB_TYPE = Types::Int32.new(0x0A0D0D0A, :little)
    # Interface Description Block type number
    IDB_TYPE = Types::Int32.new(1, :little)
    # Simple Packet Block type number
    SPB_TYPE = Types::Int32.new(3, :little)
    # Enhanced Packet Block type number
    EPB_TYPE = Types::Int32.new(6, :little)

    # Various LINKTYPE values from http://www.tcpdump.org/linktypes.html
    # FIXME: only ETHERNET type is defined as this is the only link layer
    # type supported by PacketGen
    LINKTYPE_ETHERNET = 1

    # Base error class for PcapNG
    class Error < PacketGen::Error; end
    # Invalid PcapNG file error
    class InvalidFileError < Error; end

  end

end


require_relative 'pcapng/block.rb'
require_relative 'pcapng/unknown_block.rb'
require_relative 'pcapng/shb.rb'
require_relative 'pcapng/idb.rb'
require_relative 'pcapng/epb.rb'
require_relative 'pcapng/spb.rb'
require_relative 'pcapng/file.rb'
