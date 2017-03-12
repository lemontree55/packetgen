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
      class Binding < Struct.new(:key, :value)
        # Check +fields+ responds to binding
        # @param [Types::Fields] fields
        # @return [Boolean]
        def check?(fields)
          case self[:value]
          when Proc
            self[:value].call fields.send(self[:key])
          else
            fields.send(self[:key]) == self[:value]
          end
        end

        # Set +fields+ field to binding value
        # @param [Types::Fields] fields
        # @return [void]
        def set(fields)
          case self[:value]
          when Proc
            fields.send "#{self[:key]}=", self[:value].call(nil)
          else
            fields.send "#{self[:key]}=", self[:value]
          end
        end
      end

      # @api private
      # Class to handle header associations
      class Bindings
        include Enumerable

        # op type
        # @return [:or,:and]
        attr_accessor :op
        # @return [Array<Binding>]
        attr_accessor :bindings

        # @param [:or, :and] op
        def initialize(op)
          @op = op
          @bindings = []
        end

        # @param [Object] arg
        # @return [Bindings] self
        def <<(arg)
          @bindings << arg
        end

        # each iterator
        # @return [void]
        def each
          @bindings.each { |b| yield b }
        end

        # @return [Boolean]
        def empty?
          @bindings.empty?
        end

        # @return [Hash]
        def to_h
          hsh = {}
          each { |b| hsh[b.key] = b.value }
          hsh
        end

        # Check +fields+ responds to set of bindings
        # @param [Types::Fields] fields
        # @return [Boolean]
        def check?(fields)
          case @op
          when :or
            empty? || @bindings.any? { |binding| binding.check?(fields) }
          when :and
            @bindings.all? { |binding| binding.check?(fields) }
          end
        end

        # Set +fields+ to bindings value
        # @param [Types::Fields] fields
        # @return [void]
        def set(fields)
          @bindings.each { |b| b.set fields }
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
      #   Header1.bind_header Header2, field1: 43
      #   Header1.bind_header Header2, field1: 43, field2: 43
      #   Header1.bind_header Header2, op: :and, field1: 43, field2: 43
      #   Header1.bind_header Header2, field1: ->(v) { v.nil? ? 128 : v > 127 }
      # @param [Class] header_klass header class to bind to current class
      # @param [Hash] args current class fields and their value when +header_klass+
      #  is embedded in current class. Given value may be a lambda, whose alone argument
      #  is the value extracted from header field (or +nil+ when lambda is used to set
      #  field while adding a header).
      #
      #  If multiple fields are given, a special key +:op+ may be given to set parse
      #  operation on this binding. By default, +:op+ is +:or+ (at least one binding
      #  must match to parse it). It also may be set to +:and+ (all bindings must match
      #  to parse it).
      # @return [void]
      def self.bind_header(header_klass, args={})
        op = args.delete(:op) || :or
        if @known_headers[header_klass].nil? || @known_headers[header_klass].op != op
          bindings = Bindings.new(op)
          @known_headers[header_klass] = bindings
        else
          bindings = @known_headers[header_klass]
        end
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

      # Return header protocol name
      # @return [String]
      def protocol_name
        self.class.to_s.sub(/.*::/, '')
      end

      # @abstract Should be redefined by subclasses. This method should check invariant
      #   fields from header.
      # Call by {Packet#parse} when guessing first header to check if header is correct
      # @return [Boolean]
      def parse?
        true
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
