require 'packetgen/version'

# @author Sylvain Daubert
module PacketGen

  # Shortcut for {Packet.gen}
  # @param [String] protocol base protocol for packet
  # @param [Hash] options specific options for +protocol+
  # @return [Packet]
  def self.gen(protocol, options={})
    Packet.gen protocol, options
  end

  # Shortcut for {Packet.parse}
  # @param [String] binary_str
  # @return [Packet]
  def self.parse(binary_str)
    Packet.parse binary_str
  end

  # Shortcut for {Packet.capture}
  # @param [String] iface interface name
  # @param [Hash] options capture options. See {Packet.capture}.
  # @yieldparam [Packet] packet
  # @return [Array<Packet>]
  def self.capture(iface, options={})
    Packet.capture(protocol, options) { |packet| yield packet }
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
end

require 'packetgen/structfu'
require 'packetgen/packet'
require 'packetgen/pcapng'
