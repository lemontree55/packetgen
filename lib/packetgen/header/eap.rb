# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # Extensible Authentication Protocol (EAP),
    # {https://tools.ietf.org/html/rfc3748 RFC 3748}
    #
    # A EAP header has:
    # * a {#code} field (+BinStruct::Int8Enum+),
    # * a {#id} field (+BinStruct::Int8+),
    # * a {#length} field (+BinStruct::Int16+).
    # Request (code 1) and Response (code 2) packets also have:
    # * a {#type} field (+BinStruct::Int8Enum+).
    # And Expanded Types (type 254) packets also have:
    # * a {#vendor_id} field (+BinStruct::Int24+),
    # * a {#vendor_type} field (+BinStruct::Int32+).
    # Finally, all packets have a {#body} (+BinStruct::String+).
    #
    # === Specialized headers
    # Some EAP has a specialized class:
    # * EAP-MD5 ({EAP::MD5}),
    # * EAP-TLS ({EAP::TLS}),
    # * EAP-TTLS ({EAP::TTLS}),
    # * EAP-FAST ({EAP::FAST}).
    #
    # == Header accessors
    # EAP headers may be accessed through +Packet#eap+ accessor.
    # As EAP has specialized subclasses ({EAP::MD5}, {EAP::TLS}, {EAP::TTLS} and
    # {EAP::FAST}), these headers may be accessed through +#eap_md5+, +#eap_tls+,
    # +#eap_ttls+ and +#eap_fast+, respectively. But +#eap+ is still here as a
    # shortcut.
    #
    # == Parse EAP packets
    # When parsing an EAP packet, EAP subclass may be created from +type+ value.
    #
    # So result of parsing a EAP header may be a {EAP}, {EAP::MD5}, {EAP::TLS},
    # {EAP::TTLS} or {EAP::FAST} instance. But this instance is still accessible
    # through +Packet#eap+.
    #
    # @example Create EAP headers
    #   # create a request header with default type (1)
    #   eap = PacketGen::Header::EAP.new(code: 1)
    #   eap.human_code   #=> 'Request'
    #   # the same
    #   eap = PacketGen::Header::EAP.new(code: 'Request')
    #   eap.code         #=> 1
    #   # create a Response header of type Nak
    #   nak = PacketGen::Header::EAP.new(code: 'Response', type: 'Nak')
    #   nak.code      #=> 2
    #   nak.type      #=> 3
    #
    # @example Create a specialized EAP header
    #   eap = PacketGen::Header::EAP::TLS.new(code: 2)
    #   eap.class    #=> PacketGen::Header::EAP::TLS
    #
    # @example Parse a specialized class from a binary string
    #   pkt = PacketGen.parse("\x01\x00\x00\x0e\x04\x04\x00\x01\x02\x03name", first_header: 'EAP')
    #   pkt.eap.class   # => PacketGen::Header::EAP::MD5
    #
    # @author Sylvain Daubert
    # @author LemonTree55
    # @since 2.1.4
    class EAP < Base
      # EAP known codes
      CODES = {
        'Request' => 1,
        'Response' => 2,
        'Success' => 3,
        'Failure' => 4
      }.freeze

      # EAP known request/response types
      TYPES = {
        'Identity' => 1,
        'Notification' => 2,
        'Nak' => 3,
        'MD5-Challenge' => 4,
        'One Time Password' => 5,
        'Generic Token Card' => 6,
        'EAP-TLS' => 13,
        'EAP-TTLS' => 21,
        'EAP-FAST' => 43,
        'Expanded Types' => 254,
        'Experimental Use' => 255
      }.freeze

      # @!attribute code
      #  8-bit EAP code. See {CODES known EAP codes}
      #  @return [Integer]
      define_attr :code, BinStruct::Int8Enum, enum: CODES

      # @!attribute id
      #  8-bit identifier
      #  @return [Integer]
      define_attr :id, BinStruct::Int8

      # @!attribute length
      #  16-bit length of EAP packet
      #  @return [Integer]
      define_attr :length, BinStruct::Int16, default: 4

      # @!attribute type
      #  8-bit request or response type.
      #  This field is present only for Request or Response packets.
      #  See {TYPES known EAP types}.
      #  @return [Integer]
      define_attr :type, BinStruct::Int8Enum,
                  enum: TYPES,
                  optional: lambda(&:type?)

      # @!attribute vendor_id
      #  24-bit vendor ID.
      #  This field is present only for Request or Response packets,
      #  with type equal to +Expanded Types+ (254).
      #  @return [Integer]
      define_attr :vendor_id, BinStruct::Int24,
                  optional: ->(eap) { eap.type? && (eap.type == 254) }

      # @!attribute vendor_type
      #  32-bit vendor type.
      #  This field is present only for Request or Response packets,
      #  with type equal to +Expanded Types+ (254).
      #  @return [Integer]
      define_attr :vendor_type, BinStruct::Int32,
                  optional: ->(eap) { eap.type? && (eap.type == 254) }

      # @!attribute body
      #  EAP packet body
      #  @return [BinStruct::String, Headerable]
      define_attr :body, BinStruct::String

      # @return [EAP]
      def initialize(options={})
        super
        calc_length if options[:length].nil?
      end

      # @private
      alias old_read read

      # Populate object from a binary string
      # @param [String] str
      # @return [EAP] may return a subclass object if a more specific class
      #   may be determined
      def read(str)
        super
        return self unless self.instance_of?(EAP)
        return self unless type?

        case self.type
        when 4
          EAP::MD5.new.read(str)
        when 13
          EAP::TLS.new.read(str)
        when 21
          EAP::TTLS.new.read(str)
        when 43
          EAP::FAST.new.read(str)
        else
          self
        end
      end

      # Get human readable code
      # @return [String]
      def human_code
        self[:code].to_human
      end

      # Get human readable type
      # @return [String]
      # @raise [ParseError] not a Request nor a Response packet
      def human_type
        raise ParseError, 'not a Request nor a Response' unless type?

        self[:type].to_human
      end

      # Is packet a request?
      # @return [Boolean]
      def request?
        code == CODES['Request']
      end

      # Is packet a response?
      # @return [Boolean]
      def response?
        code == CODES['Response']
      end

      # Is packet a success?
      # @return [Boolean]
      def success?
        code == CODES['Success']
      end

      # Is packet a failure?
      # @return [Boolean]
      def failure?
        code == CODES['Failure']
      end

      # Is packet a NAK?
      # @return [Boolean]
      # @since 4.1.0
      # @author LemonTree55
      def nak?
        (code == 2) && (type == 3)
      end

      # Return an array of desired authentication types from a Nak packet
      # @return [Array<Integer>]
      # @raise [ParseError] not a Nak packet
      def desired_auth_type
        raise ParseError, 'not a Nak response' unless nak?

        body.to_s.unpack('C*')
      end

      # Calculate length field from content
      # @return [Integer]
      def calc_length
        Base.calculate_and_set_length(self)
      end

      # Say is this EAP header has {#type} field
      # @return [Boolean]
      # @since 2.7.0
      def type?
        [1, 2].include?(self.code)
      end

      # Callback called when a EAP header is added to a packet
      # Here, add +#eap+ method as a shortcut to existing
      # +#eap_(md5|tls|ttls|fast)+.
      # @param [Packet] packet
      # @return [void]
      def added_to_packet(packet)
        return if packet.respond_to?(:eap)

        packet.instance_eval("def eap(arg=nil); header(#{self.class}, arg); end") # def eap(arg=nil); header(EAP, arg); end
      end

      # Invert between a request and a response packet. Not action for
      # others codes.
      # @return [self]
      def reply!
        case self.code
        when 1 then self.code = 2
        when 2 then self.code = 1
        end
        self
      end
    end

    Dot1x.bind EAP, type: 0
  end
end

require_relative 'eap/md5'
require_relative 'eap/tls'
require_relative 'eap/ttls'
require_relative 'eap/fast'
