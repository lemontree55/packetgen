# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # Extensible Authentication Protocol (EAP),
    # {https://tools.ietf.org/html/rfc3748 RFC 3748}
    #
    # A EAP header has:
    # * a {#code} field ({Types::Int8Enum}),
    # * a {#id} field ({Types::Int8}),
    # * a {#length} field ({Types::Int16}).
    # Request (code 1) and Response (code 2) packets also have:
    # * a {#type} field (+Types::Int8Enum+).
    # And Expanded Types (type 254) packets also have:
    # * a {#vendor_id} field ({Types::Int24}),
    # * a {#vendor_type} field ({Types::Int32}).
    # Finally, all packets have a {#body} ({Types::String}).
    # @author Sylvain Daubert
    class EAP < Base

      # EAP known codes
      CODES = {
        'Request'   => 1,
        'Response'  => 2,
        'Success'   => 3,
        'Failure'   => 4
      }
      
      # EAP known request/response types
      TYPES = {
        'Identity'           => 1,
        'Notification'       => 2,
        'Nak'                => 3,
        'MD5-Challenge'      => 4,
        'One Time Password'  => 5,
        'Generic Token Card' => 6,
        'EAP-TLS'            => 13,
        'EAP-TTLS'           => 21,
        'EAP-FAST'           => 43,
        'Expanded Types'     => 254,
        'Experimental Use'   => 255
      }

      # @!attribute code
      #  @return [Integer] 8-bit EAP code
      define_field :code, Types::Int8Enum, enum: CODES

      # @!attribute id
      #  @return [Integer] 8-bit identifier
      define_field :id, Types::Int8

      # @!attribute length
      #  @return [Integer] 16-bit length of EAP packet
      define_field :length, Types::Int16, default: 4
      
      # @!attribute type
      #  This field is present only for Request or Response packets,
      #  with type different from Expanded Types (254).
      #  @return [Integer] 8-bit request or response type
      define_field :type, Types::Int8Enum, enum: TYPES, 
                   optional: ->(eap) { [1, 2].include? eap.code }
                   
      # @!attribute vendor_id
      #  This field is present only for Request or Response packets,
      #  with type equal to +Expanded Types+ (254).
      #  @return [Integer] 24-bit vendor ID
      define_field :vendor_id, Types::Int24,
                   optional: ->(eap) { [1, 2].include?(eap.code) and eap.type == 254 }
      
      # @!attribute vendor_type
      #  This field is present only for Request or Response packets,
      #  with type equal to +Expanded Types+ (254).
      #  @return [Integer] 32-bit vendor type
      define_field :vendor_type, Types::Int32,
                   optional: ->(eap) { [1, 2].include?(eap.code) and eap.type == 254 }

      # @!attribute body
      #  @return [Types::String, Header::Base]
      define_field :body, Types::String
      
      # @return [EAP]
      def initialize(options={})
        super
        calc_length if options[:length].nil?
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
        raise ParseError, 'not a Request nor a Response' unless [1,2].include?(code)
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
        if code != 2 and type != 3
          raise ParseError, 'not a Nak response'
        end
        body.to_s.unpack('C*')
      end
      
      # Calculate length field from content
      # @return [Integer]
      def calc_length
        self.length = sz
      end
    end
    
    Dot1x.bind_header EAP, type: 0
  end
end

require_relative 'eap/md5'
require_relative 'eap/tls'
require_relative 'eap/ttls'
require_relative 'eap/fast'
