# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    # @abstract Base class for all header types.
    #    Subclasses may define magic methods:
    #    * +#calc_checksum+, which computes header checksum,
    #    * +#calc_length+, which computes header length,
    #    * {#parse?},
    #    * +#reply!+, which inverts needed fields to forge a response.
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
            attr = if self[:key].to_s.end_with?('?')
                     self[:key].to_s[0..-2]
                   else
                     self[:key]
                   end
            fields.send "#{attr}=", self[:value]
          end
        end
      end

      # @api private
      # Class to handle a header association from procs
      class ProcBinding
        # @param [Array<Proc>] procs first proc is used to set fields, second proc is
        #  used to check binding
        def initialize(procs)
          @set = procs.shift
          @check = procs.shift
        end

        # Check +fields+ responds to binding
        # @param [Types::Fields] fields
        # @return [Boolean]
        def check?(fields)
          @check.call(fields)
        end

        # Set +fields+ field to binding value
        # @param [Types::Fields] fields
        # @return [void]
        def set(fields)
          @set.call(fields)
        end
      end

      # @api private
      # Class to handle header associations
      class Bindings
        include Enumerable

        # @return [Array<Binding>]
        attr_accessor :bindings

        def initialize
          @bindings = []
        end

        def new_set
          @bindings << []
        end

        # @param [Object] arg
        # @return [Bindings] self
        def <<(arg)
          @bindings.last << arg
        end

        # each iterator
        # @return [void]
        def each
          @bindings.each do |b|
            yield b
          end
        end

        # @return [Boolean]
        def empty?
          @bindings.empty?
        end

        # Return binding as a hash.
        # @return [Hash]
        def to_h
          hsh = {}
          each do |b|
            b.each { |sb| hsh[sb.key] = sb.value }
          end
          hsh
        end

        # Check +fields+ responds to set of bindings
        # @param [Types::Fields] fields
        # @return [Boolean]
        def check?(fields)
          @bindings.any? { |group| group.all? { |binding| binding.check?(fields) } }
        end

        # Set +fields+ to bindings value
        # @param [Types::Fields] fields
        # @return [void]
        def set(fields)
          @bindings.first.each { |b| b.set fields }
        end
      end

      # Reference on packet which owns this header
      # @return [Packet,nil]
      attr_reader :packet

      # @private
      # On inheritage, create +@known_header+ class variable
      # @param [Class] klass
      # @return [void]
      def self.inherited(klass)
        super
        klass.class_eval { @known_headers = {} }
      end

      # Bind a upper header to current one.
      # @param [Class] header_klass header class to bind to current class
      # @param [Hash] args current class fields and their value when +header_klass+
      #   is embedded in current class.
      #
      #   Given value may be a lambda, whose alone argument is the value extracted
      #   from header field (or +nil+ when lambda is used to set  field while adding
      #   a header).
      #
      #   Special key +procs+ may be used to set 2 lambdas, the former to set
      #   fields, the latter to check bindings. This may be used when multiple and
      #   non-trivial checks should be made.
      # @return [void]
      # @example Basic examples
      #   # Bind Header2 to Header1 when field1 from Header1 has a value of 42
      #   Header1.bind Header2, field1: 42
      #   # Bind Header3 to Header1 when field1 from Header1 has a value of 43
      #   # and field2 has value 43 or 44
      #   Header1.bind Header3, field1: 43, field2: 43
      #   Header1.bind Header3, field1: 43, field2: 44
      # @example Defining a binding on a field using a lambda.
      #   # Bind Header4 to Header1 when field1 from Header1 has a value
      #   # greater or equal to 44. When adding a Header2 to a Header1
      #   # with Packet#add, force value to 44.
      #   Header1.bind Header4, field1: ->(v) { v.nil? ? 44 : v >= 44 }
      # @example Defining a binding using procs key
      #   # Bind Header5 to Header1 when field1 from Header1 has a value of 41
      #   # and first two bytes of header1's body are null.
      #   # When adding a Header2 to a Header1 with Packet#add, force value to 44.
      #   Header1.bind Header5, procs: [->(hdr) { hdr.field1 = 41 }
      #                                 ->(hdr) { hdr.field1 == 41 && hdr.body[0..1] == "\x00\x00" }]
      # @since 2.7.0
      def self.bind(header_klass, args={})
        if @known_headers[header_klass].nil?
          bindings = Bindings.new
          @known_headers[header_klass] = bindings
        else
          bindings = @known_headers[header_klass]
        end
        bindings.new_set
        args.each do |key, value|
          bindings << if key == :procs
                        ProcBinding.new(value)
                      else
                        Binding.new(key, value)
                      end
        end
      end

      # Give protocol name for this class
      # @return [String]
      # @since 2.0.0
      def self.protocol_name
        return @protocol_name if @protocol_name

        classname = to_s
        @protocol_name = if classname.start_with?('PacketGen::Header')
                           classname.sub(/.*Header::/, '')
                         else
                           classname.sub(/.*::/, '')
                         end
      end

      # Helper method to calculate length of +hdr+ and set its +length+ field.
      # To be used by +#calc_length+ in Base subclasses.
      # @param [Base] hdr
      # @param [Boolean] header_in_size if +true+ header is included in length,
      #   if +false+, only +body+ is taken into account
      def self.calculate_and_set_length(hdr, header_in_size: true)
        length = if header_in_size
                   hdr.sz
                 else
                   hdr.body.sz
                 end
        hdr.length = length
      end

      # @api private
      # Get known headers
      # @return [Hash] keys: header classes, values: hashes
      def self.known_headers
        @known_headers
      end

      # @see Types::Fields#initialize
      def initialize(options={})
        @packet = options.delete(:packet) if options.key?(:packet)
        super
      end

      # Return header protocol name
      # @return [String]
      def protocol_name
        self.class.protocol_name
      end

      # return header method name
      # @return [String]
      # @since 2.0.0
      # @since 2.8.6 permit multiple nesting levels
      def method_name
        return @method_name if @method_name

        @method_name = protocol_name.downcase.gsub(/::/, '_')
      end

      # @abstract Should be redefined by subclasses. This method should check invariant
      #   fields from header.
      # Call by {Packet#parse} when guessing first header to check if header is correct
      # @return [Boolean]
      def parse?
        true
      end

      # @api private
      # Set packet to which this header belongs
      # @param [Packet] packet
      # @return [Packet] packet
      # @since 2.1.4
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

      # @api private
      # Get +header+ id in {Packet#headers} array
      # @param [Header] header
      # @return [Integer]
      # @raise [FormatError] +header+ not in a packet
      def header_id(header)
        raise FormatError, "header of type #{header.class} not in a packet" if packet.nil?
        id = packet.headers.index(header)
        if id.nil?
          raise FormatError, "header of type #{header.class} not in packet #{packet}"
        end
        id
      end

      # @api private
      # Get {IP} or {IPv6} previous header from +header+
      # @param [Header] header
      # @return [Header]
      # @raise [FormatError] no IP or IPv6 header previous +header+ in packet
      # @raise [FormatError] +header+ not in a packet
      def ip_header(header)
        hid = header_id(header)
        iph = packet.headers[0...hid].reverse.find { |h| h.is_a?(IP) || h.is_a?(IPv6) }
        raise FormatError, 'no IP or IPv6 header in packet' if iph.nil?
        iph
      end

      # @api private
      # Get link layer header from given header
      # @param [Header] header
      # @return [Header]
      # @raise [FormatError] no link layer header in packet
      # @raise [FormatError] +header+ not in a packet
      def ll_header(header)
        hid = header_id(header)
        llh = packet.headers[0...hid].reverse.find { |h| h.is_a?(Eth) || h.is_a?(Dot11) }
        raise FormatError, 'no link layer header in packet' if llh.nil?
        llh
      end
    end
  end
end
