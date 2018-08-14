# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

require 'rasn1'

module PacketGen
  module Header
    # @abstract Base class for ASN.1 header types.
    #    This class implement minimal {Base} API to mimic a {Base} object.
    #
    #    Subclasses may define magic methods:
    #    * {#parse?}.
    # @author Sylvain Daubert
    # @since 2.0.0
    class ASN1Base < RASN1::Model
      # Reference on packet which owns this header
      # @return [Packet,nil]
      attr_reader :packet

      # Give protocol name for this class
      # @return [String]
      # @since 2.0.0
      def self.protocol_name
        self.new.protocol_name
      end

      # Define some methods from given ASN.1 fields to mimic {Base} attributes
      # @param [Array<Symbol>] attributes
      # @return [void]
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

      # Called by {Packet#parse} when guessing first header to check if header
      # is correct
      # @return [true]
      def parse?
        true
      end

      # @api private
      # @since 2.1.4
      # Set packet to which this header belongs
      # @param [Packet] packet
      # @return [Packet] packet
      def packet=(packet)
        @packet = packet
        added_to_packet(packet)
        @packet
      end

      # @abstract This method is called when a header is added to a packet.
      #   This base method does nothing but may be overriden by subclasses.
      # @param [Packet] packet packet to which self is added
      # @return [void]
      # @since 2.1.4
      def added_to_packet(packet) end

      alias parse parse!
      alias to_s to_der

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
    end
  end
end
