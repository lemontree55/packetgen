require 'packetgen/version'

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
    Packet.parse binary_str, first_header
  end

  # Shortcut for {Packet.capture}
  # @param [String] iface interface name
  # @param [Hash] options capture options. See {Packet.capture}.
  # @yieldparam [Packet] packet
  # @return [Array<Packet>]
  def self.capture(iface, options={})
    Packet.capture(iface, options) { |packet| yield packet }
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
    str.force_encoding Encoding::BINARY
  end

  # Get default network interface (ie. first non-loopback declared interface)
  # @return [String]
  def self.default_iface
    return @default_iface if @default_iface

    ipaddr = `ip addr`.split("\n")
    @default_iface = ipaddr.each_with_index do |line, i|
      m = line.match(/^\d+: (\w+\d+):/)
      next if m.nil?
      next if m[1] == 'lo'
      break m[1]
    end
  end
end

require 'packetgen/structfu'
require 'packetgen/packet'
require 'packetgen/capture'
require 'packetgen/pcapng'
