# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # @abstract
    # Base class for all header types
    # @author Sylvain Daubert
    class Base < Types::Fields

      # @api private
      # Simple class to handle a header association
      Binding = Struct.new(:key, :value)

      # @api private
      # Class to handle header associations
      class Bindings
        include Enumerable
        attr_accessor :op
        attr_accessor :bindings

        # @param [:or, :and] op
        def initialize(op)
          @op = op
          @bindings = []
        end

        def <<(arg)
          @bindings << arg
        end

        def each
          @bindings.each { |b| yield b }
        end
      end

      # @api private
      # Reference on packet which owns this header
      attr_accessor :packet

      # On inheritage, create +@known_headers+ class variable
      # @param [Class] klass
      # @return [void]
      def self.inherited(klass)
        super
        klass.class_eval { @known_headers = {} }
      end

      # Bind a upper header to current class
      # @param [Class] header_klass header class to bind to current class
      # @param [Hash] args current class fields and their value when +header_klass+
      #  is embedded in current class. If multiple fields are given, a special key
      #  +:op+ may be given to set parse operation on this binding. By default, +:op+
      #  is +:or+ (at least one binding must match to parse it). It also may be set
      #  to +:and+ (all bindings must match to parse it).
      # @return [void]
      def self.bind_header(header_klass, args={})
        op = args.delete(:op) || :or
        bindings = Bindings.new(op)
        @known_headers[header_klass] = bindings
        args.each do |key, value|
          bindings << Binding.new(key, value)
        end
      end

      # @api private
      # Get knwon headers
      # @return [Hash] keys: header classes, values: hashes
      def self.known_headers
        @known_headers
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
