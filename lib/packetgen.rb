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
  # @param [String] first_layer First protocol layer
  # @return [Packet]
  def self.parse(binary_str, first_layer: 'Eth')
    Packet.parse binary_str, first_layer
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
end

require 'packetgen/structfu'
require 'packetgen/packet'
