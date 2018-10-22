# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

require 'packetgen/version'
require 'interfacez'

# PacketGen is a network packet generator and analyzor.
# @author Sylvain Daubert
module PacketGen
  # Base exception class for PacketGen exceptions
  class Error < StandardError; end

  # Packet badly formatted
  class FormatError < Error; end

  # Parsing error
  class ParseError < Error; end

  # Sending packet on wire error
  class WireError < Error; end

  # Shortcut for {Packet.gen}
  # @param [String] protocol base protocol for packet
  # @param [Hash] options specific options for +protocol+
  # @return [Packet]
  def self.gen(protocol, options={})
    Packet.gen protocol, options
  end

  # Shortcut for {Packet.parse}
  # @param [String] binary_str
  # @param [String] first_header First protocol header
  # @return [Packet]
  def self.parse(binary_str, first_header: nil)
    Packet.parse binary_str, first_header: first_header
  end

  # Shortcut for {Packet.capture}
  # @param [Hash] options capture options. See {Packet.capture}.
  # @yieldparam [Packet] packet
  # @return [Array<Packet>]
  def self.capture(options={})
    Packet.capture(options) { |packet| yield packet if block_given? }
  end

  # Shortcut for {Packet.read}
  # @param [String] filename PcapNG file
  # @return [Array<Packet>]
  def self.read(filename)
    Packet.read filename
  end

  # Shortcut for {Packet.write}
  # @param [String] filename
  # @param [Array<Packet>] packets packets to write
  # @return [void]
  def self.write(filename, packets)
    Packet.write filename, packets
  end

  # Force binary encoding for +str+
  # @param [String] str
  # @return [String] binary encoded string
  def self.force_binary(str)
    str.dup.force_encoding(Encoding::BINARY)
  end

  # Get default network interface (ie. first non-loopback declared interface)
  # @return [String]
  def self.default_iface
    Interfacez.default
  end

  # Shortcut to get a header class
  # @example builtin class
  #   # same as PacketGen::Header::Dot11:Data.new(id: 0xfedc)
  #   dot11 = PacketGen.header('Dot11::Data', id: 0xfedc)  #=> PacketGen::Header::Dot11:Data
  # @example plugin class
  #   require 'packet-plugin-smb'
  #   # same as PacketGen::Plugin::SMB::CloseRequest.new(fid: 0x1234)
  #   smbclose = PacketGen.header('SMB::CloseRequest', fid: 0x1234)
  # @param [String] protocol protocol from which generate a header
  # @param [Hash] options specific options for +protocol+
  # @return [Header::Base]
  def self.header(protocol, options={})
    Header.get_header_class_by_name(protocol).new(options)
  end
end

require 'packetgen/deprecation'
require 'packetgen/types'
require 'packetgen/inspect'
require 'packetgen/pcapng'
require 'packetgen/packet'
require 'packetgen/capture'
require 'packetgen/proto'
