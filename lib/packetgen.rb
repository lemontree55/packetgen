# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require 'packetgen/version'
require 'bin_struct'
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

  # No known binding
  class BindingError < Error
    # @return [Headerable]
    attr_reader :prev_hdr
    # @return [Headerable]
    attr_reader :hdr

    def initialize(prev_hdr, hdr)
      super()
      @prev_hdr = prev_hdr
      @hdr = hdr
    end

    def message
      "#{prev_hdr.class} knowns no layer association with #{hdr.protocol_name}. " \
        "Try #{prev_hdr.class}.bind_layer(#{hdr.class}, " \
        "#{prev_hdr.method_name}_proto_field: " \
        "<value_for_#{hdr.method_name}>)"
    end
  end

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
  # Same arguments as {Capture#initialize}
  # @see Capture#initialize
  # @yieldparam [Packet,String] packet
  # @yieldparam [Time] timestamp
  # @return [Array<Packet>]
  # @since 3.3.0 add packet timestamp as second yield parameter
  def self.capture(**kwargs)
    Packet.capture(**kwargs) { |packet| yield packet if block_given? }
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
    Deprecation.deprecated(self, :force_binary, "String#b")
    str.b
  end

  # Get default network interface (ie. first non-loopback declared interface)
  # @return [String]
  def self.default_iface
    return @default_iface if defined? @default_iface

    Interfacez.raw_interface_addresses.each do |iface|
      next unless iface.broadaddr
      next unless Interfacez.ipv4_address_of(iface.name)
      next unless Interfacez.ipv6_address_of(iface.name)

      @default_iface = iface.name
      break
    end
  end

  # Get loopback network interface
  # @return [String]
  def self.loopback_iface
    Interfacez.loopback
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
require 'packetgen/inspect'
require 'packetgen/pcapng'
require 'packetgen/pcap'
require 'packetgen/packet'
require 'packetgen/unknown_packet'
require 'packetgen/capture'
require 'packetgen/inject'
require 'packetgen/proto'
