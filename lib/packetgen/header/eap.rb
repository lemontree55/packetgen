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
    # == Create EAP headers
    # An EAP header may be created this way:
    #   # create a request header with default type (1)
    #   eap = EAP.new(code: 1)   # => PacketGen::Header::EAP
    #   # the same
    #   eap = EAP.new(code: 'Request')   # => PacketGen::Header::EAP
    #   # create a Response header of type Nak
    #   nak = EAP.new(code: 'Response', type: 'Nak')
    #
    # === Specialized headers
    # Some EAP has a specialized class:
    # * EAP-MD5,
    # * EAP-TLS,
    # * EAP-TTLS,
    # * EAP-FAST.
    # Creating such a header is fairly simple:
    #   # Generate a EAP-TLS Response (type is forced to 13)
    #   eap = EAP::TLS.new(code: 2)     # => PacketGen::Header::EAP::TLS
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
    # @author Sylvain Daubert
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
      #  @return [Integer] 8-bit EAP code
      define_attr :code, BinStruct::Int8Enum, enum: CODES

      # @!attribute id
      #  @return [Integer] 8-bit identifier
      define_attr :id, BinStruct::Int8

      # @!attribute length
      #  @return [Integer] 16-bit length of EAP packet
      define_attr :length, BinStruct::Int16, default: 4

      # @!attribute type
      #  This field is present only for Request or Response packets,
      #  with type different from Expanded Types (254).
      #  @return [Integer] 8-bit request or response type
      define_attr :type, BinStruct::Int8Enum,
                  enum: TYPES,
                  optional: lambda(&:type?)

      # @!attribute vendor_id
      #  This field is present only for Request or Response packets,
      #  with type equal to +Expanded Types+ (254).
      #  @return [Integer] 24-bit vendor ID
      define_attr :vendor_id, BinStruct::Int24,
                  optional: ->(eap) { eap.type? && (eap.type == 254) }

      # @!attribute vendor_type
      #  This field is present only for Request or Response packets,
      #  with type equal to +Expanded Types+ (254).
      #  @return [Integer] 32-bit vendor type
      define_attr :vendor_type, BinStruct::Int32,
                  optional: ->(eap) { eap.type? && (eap.type == 254) }

      # @!attribute body
      #  @return [BinStruct::String, Header::Base]
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
      # @return [Dot11] may return a subclass object if a more specific class
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

      # Return an array of desired authentication types from a Nak packet
      # @return [Array<Integer>]
      # @raise [ParseError] not a Nak packet
      def desired_auth_type
        raise ParseError, 'not a Nak response' if (code != 2) && (type != 3)

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
