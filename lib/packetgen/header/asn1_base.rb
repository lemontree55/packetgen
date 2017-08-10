# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'rasn1'

module PacketGen
  module Header

    # @abstract Base class for ASN.1 header types.
    #    Subclasses may define magic methods:
    #    * {#parse?}.
    # @author Sylvain Daubert
    class ASN1Base < RASN1::Model

      # @api private
      # Reference on packet which owns this header
      attr_accessor :packet

      # Give protocol name for this class
      # @return [String]
      # @since 2.0.0
      def self.protocol_name
        self.new.protocol_name
      end

      def self.define_attributes(*attributes)
        @attributes = attributes
        attributes.each do |attr|
          class_eval "def #{attr}; @elements[:#{attr}].value; end\n" \
                     "def #{attr}=(v); @elements[:#{attr}].value = v; end"
        end
      end

      # Return header protocol name
      # @return [String]
      def protocol_name
        return @protocol_name if @protocol_name

        classname = self.class.to_s
        @protocol_name = if classname.start_with?('PacketGen::Header')
                           classname.sub(/.*Header::/, '')
                         else
                           classname.sub(/.*::/, '')
                         end
      end
      # return header method name
      # @return [String]
      # @since 2.0.0
      def method_name
        return @method_name if @method_name

        @method_name = protocol_name.downcase.sub(/::/, '_')
      end

      # @return [true]
      def parse?
        true
      end

      alias :parse :parse!
      alias :to_s :to_der

      # Read a BER string
      # @param [String] str
      # @return [ASN1Base] self
      def read(str)
        parse(str, ber: true)
        self
      end

      # Common inspect method for ASN.1 headers
      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        self.class.class_eval { @attributes }.each do |attr|
          str << Inspect.inspect_asn1_attribute(attr, self[attr], 2)
        end
        str
      end

      # @api private
      # Get +header+ id in packet headers array
      # @param [Header] header
      # @return [Integer]
      # @raise FormatError +header+ not in a packet
      def header_id(header)
        raise FormatError, "header of type #{header.class} not in a packet" if packet.nil?
        id = packet.headers.index(header)
        if id.nil?
          raise FormatError, "header of type #{header.class} not in packet #{packet}"
        end
        id
      end

      # @api private
      # Get IP or IPv6 previous header from +header+
      # @param [Header] header
      # @return [Header]
      # @raise FormatError no IP or IPv6 header previous +header+ in packet
      # @raise FormatError +header+ not in a packet
      def ip_header(header)
        hid = header_id(header)
        iph = packet.headers[0...hid].reverse.find { |h| h.is_a? IP or h.is_a? IPv6 }
        raise FormatError, 'no IP or IPv6 header in packet' if iph.nil?
        iph
      end
    end
  end
end
