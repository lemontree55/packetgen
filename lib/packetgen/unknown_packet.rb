# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  # Unknown packet, minimaly mimicking a {Packet}.
  #
  # An unknown packet is generated when capturing packets, and a packet cannot
  # be parsed.
  # @since 3.2.0
  class UnknownPacket
    # List of headers. Always empty
    # @return [Array]
    attr_reader :headers

    def initialize
      @headers = [].freeze
      @binary_str = ::String.new # Return empty string with encoding ASCII-8BIT, so BINARY
    end

    # Unknown packet, so unknown protocol.
    # @return [false]
    def is?(_protocol)
      false
    end

    # Get packet body
    # @return [String]
    def body
      @binary_str
    end
    alias to_s body

    # Set packet body
    # @param [String] str
    # @return [void]
    def body=(str)
      @binary_str = str.b
    end

    # Write packet to a PCapNG file on disk.
    # @param [String] filename
    # @return [Array] see return from {PcapNG::File#to_file}
    # @see File
    def to_f(filename)
      PcapNG::File.new.read_array([self]).to_f(filename)
    end
    alias write to_f

    # Read binary string
    # @param [String] binary_str
    # @return [self]
    def parse(binary_str, _first_header: nil)
      @binary_str = binary_str.b
      self
    end

    # @return [String]
    def inspect
      str = Inspect.dashed_line(self.class)
      str << Inspect.inspect_body(body)
    end

    # equality if {#to_s} are equal
    # @return [Boolean]
    def ==(other)
      to_s == other.to_s
    end

    # True only if +other+ is an {UnknownPacket} and +other == self+
    # @return [Boolean]
    def ===(other)
      case other
      when UnknownPacket
        self == other
      else
        false
      end
    end
  end
end
