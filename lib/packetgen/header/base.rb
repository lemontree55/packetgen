# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # @abstract Base class for all header types.
    #    Subclasses may define magic methods:
    #    * +#calc_checksum+, which computes header checksum,
    #    * +#calc_length+, which computes header length,
    #    * {#parse?},
    #    * +#reply!+, which inverts needed attributes to forge a response.
    # {Base} class defines {.bind} method, to bind headers to outer ones.
    # @author Sylvain Daubert
    # @author LemonTree55
    class Base < BinStruct::Struct
      include Headerable

      # @api private
      # Simple class to handle a header association
      class Binding < ::Struct.new(:key, :value)
        # Check +fields+ responds to binding
        # @param [BinStruct::Struct] fields
        # @return [Boolean]
        def check?(fields)
          case self[:value]
          when Proc
            self[:value].call(fields.send(self[:key]))
          else
            fields.send(self[:key]) == self[:value]
          end
        end

        # Set +fields+ field to binding value
        # @param [BinStruct::Struct] fields
        # @return [void]
        def set(fields)
          case self[:value]
          when Proc
            fields.send(:"#{self[:key]}=", self[:value].call(nil))
          else
            attr = if self[:key].to_s.end_with?('?')
                     self[:key].to_s[0..-2]
                   else
                     self[:key]
                   end
            fields.send(:"#{attr}=", self[:value])
          end
        end
      end

      # @api private
      # Class to handle a header association from procs
      class ProcBinding
        # @param [Array(Proc,Proc)] procs first proc is used to set fields, second proc is
        #  used to check binding
        def initialize(procs)
          @set = procs.shift
          @check = procs.shift
        end

        # Check +fields+ responds to binding
        # @param [BinStruct::Struct] fields
        # @return [Boolean]
        def check?(fields)
          @check.call(fields)
        end

        # Set +fields+ field to binding value
        # @param [BinStruct::Struct] fields
        # @return [void]
        def set(fields)
          @set.call(fields)
        end
      end

      # @api private
      # Class to handle a set of header associations ({Binding} or/and {ProcBinding})
      class Bindings
        include Enumerable

        # @return [Array<Binding,ProcBinding>]
        attr_accessor :bindings

        def initialize
          @bindings = []
        end

        def new_set
          @bindings << []
        end

        # @param [Binding,ProcBinding] arg
        # @return [Bindings] self
        def <<(arg)
          @bindings.last << arg
        end

        # each iterator
        # @return [void]
        # @yieldparam [Binding,ProcBinding] binding
        def each(&block)
          @bindings.each(&block)
        end

        # @return [Boolean]
        def empty?
          @bindings.empty?
        end

        # Return bindings as a hash.
        # @return [Hash]
        def to_h
          hsh = {}
          each do |b|
            b.each { |sb| hsh[sb.key] = sb.value }
          end
          hsh
        end

        # Check +fields+ responds to set of bindings
        # @param [BinStruct::Struct] fields
        # @return [Boolean]
        def check?(fields)
          @bindings.any? { |group| group.all? { |binding| binding.check?(fields) } }
        end

        # Set +fields+ to bindings value
        # @param [BinStruct::Struct] fields
        # @return [void]
        def set(fields)
          @bindings.first.each { |b| b.set(fields) }
        end
      end

      # @private
      # On inheritance, create +@known_header+ class variable
      # @param [Class] klass
      # @return [void]
      def self.inherited(klass)
        super
        klass.class_eval { @known_headers = {} }
      end

      class << self
        # @api private
        # Get known headers
        # @return [Hash{Headerable => Bindings}]
        attr_reader :known_headers

        # Bind a upper header to current one.
        # @param [Class] header_klass header class to bind to current class
        # @param [Hash] args current class attributes and their value when +header_klass+
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
        #   # Bind TCP to IP when protocol attribute from IP has a value of 66
        #   PacketGen::Header::IP.bind PacketGen::Header::TCP, protocol: 66
        #   # Bind UDP to IP when protocol from IP has a value of 177
        #   # and tos has value 43 or 44
        #   PacketGen::Header::IP .bind PacketGen::Header::UDP, protocol: 177, tos: 43
        #   PacketGen::Header::IP .bind PacketGen::Header::UDP, protocol: 177, tos: 44
        # @example Defining a binding on a field using a lambda.
        #   # Bind DHCP to Eth when ethertype from Eth has a value
        #   # greater or equal to 44. When adding a DHCP to a Eth
        #   # with Packet#add, force value to 44.
        #   PacketGen::Header::Eth.bind PacketGen::Header::DHCP, ethertype: ->(v) { v.nil? ? 44 : v >= 44 }
        # @example Defining a binding using procs key
        #   # Bind IPv6 to IP when protocol from IP has a value of 255
        #   # and first two bytes of IP's body are 0x6000.
        #   # When adding a IPv6 to a IP with Packet#add, force value to 255.
        #   PacketGen::Header::IP.bind PacketGen::Header::IPv6, procs: [->(hdr) { hdr.protocol = 255 },
        #                                                               ->(hdr) { hdr.protocol == 255 && hdr.body[0..1] == "\x60\x00" }]
        # @since 2.7.0
        def bind(header_klass, args={})
          bindings = @known_headers[header_klass]
          if bindings.nil?
            bindings = Bindings.new
            @known_headers[header_klass] = bindings
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

        # Helper method to calculate length of +hdr+ and set its +length+ field.
        # To be used by +#calc_length+ in Base subclasses.
        # @param [Base] hdr
        # @param [Boolean] header_in_size if +true+ header is included in length,
        #   if +false+, only +body+ is taken into account
        def calculate_and_set_length(hdr, header_in_size: true)
          length = if header_in_size
                     hdr.sz
                   else
                     hdr[:body].sz
                   end
          hdr.length = length
        end
      end

      # @see BinStruct::Struct#initialize
      def initialize(options={})
        @packet = options.delete(:packet) if options.key?(:packet)
        super
      end

      # @api private
      # Get +header+ id in {Packet#headers} array
      # @param [Header] header
      # @return [Integer] header id
      # @raise [FormatError] +header+ not in a packet
      def header_id(header)
        raise FormatError, "header of type #{header.class} not in a packet" if packet.nil?

        id = packet.headers.index(header)
        raise FormatError, "header of type #{header.class} not in packet #{packet}" if id.nil?

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
        raise FormatError, 'no IP nor IPv6 header in packet' if iph.nil?

        iph
      end

      # @api private
      # Get link layer ({Eth} or {Dot11}) header from given header
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
