# coding: utf-8
module PacketGen
  module Header
    class IKE

      # This class handles Notify payloads, as defined in RFC 7296 §3.10.
      #
      # A Notify payload contains a generic payload header (see {Payload}) and
      # some specific fields:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |  Protocol ID  |   SPI Size    |      Notify Message Type      |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                Security Parameter Index (SPI)                 ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                       Notification Data                       ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # These specific fields are:
      # * {#protocol} (type {Types::Int8}),
      # * {#spi_size} (type {Types::Int8}),
      # * {#message_type} (type {Types::Int16}),
      # * {#spi} (type {Types::String}),
      # * {#content} (type {Types::String}).
      #
      # == Create a Notify payload
      #   # Create a IKE packet with a Notify payload
      #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::Notify', protocol: 'IKE', type: 'INVALID_SYNTAX')
      #   pkt.ike_notify.spi      # => ""
      #   pkt.ike_notify.content  # => ""
      #   pkt.calc_length
      # == Create a Notify payload with a SPI
      #   # Create a IKE packet with a Notify payload
      #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::Notify', protocol: 'ESP', spi_size: 4, type: 'INVALID_SYNTAX')
      #   pkt.ike_notify.spi.read PacketGen::Types::Int32.new(0x12345678).to_s
      #   pkt.calc_length
      #   @author Sylvain Daubert
      class Notify < Payload

        # Payload type number
        PAYLOAD_TYPE = 41

        # Message types
        TYPES = {
          'UNSUPPORTED_CRITICAL_PAYLOAD'  => 1,
          'INVALID_IKE_SPI'               => 4,
          'INVALID_MAJOR_VERSION'         => 5,
          'INVALID_SYNTAX'                => 7,
          'INVALID_MESSAGE_ID'            => 9,
          'INVALID_SPI'                   => 11,
          'NO_PROPOSAL_CHOSEN'            => 14,
          'INVALID_KE_PAYLOAD'            => 17,
          'AUTHENTICATION_FAILED'         => 24,
          'SINGLE_PAIR_REQUIRED'          => 34,
          'NO_ADDITIONAL_SAS'             => 35,
          'INTERNAL_ADDRESS_FAILURE'      => 36,
          'FAILED_CP_REQUIRED'            => 37,
          'TS_UNACCEPTABLE'               => 38,
          'INVALID_SELECTORS'             => 39,
          'TEMPORARY_FAILURE'             => 43,
          'CHILD_SA_NOT_FOUND'            => 44,
          'INITIAL_CONTACT'               => 16384,
          'SET_WINDOW_SIZE'               => 16385,
          'ADDITIONAL_TS_POSSIBLE'        => 16386,
          'IPCOMP_SUPPORTED'              => 16387,
          'NAT_DETECTION_SOURCE_IP'       => 16388,
          'NAT_DETECTION_DESTINATION_IP'  => 16389,
          'COOKIE'                        => 16390,
          'USE_TRANSPORT_MODE'            => 16391,
          'HTTP_CERT_LOOKUP_SUPPORTED'    => 16392,
          'REKEY_SA'                      => 16393,
          'ESP_TFC_PADDING_NOT_SUPPORTED' => 16394,
          'NON_FIRST_FRAGMENTS_ALSO'      => 16395,
        }.freeze

        # @!attribute [r] protocol
        #  8-bit protocol ID. If this notification concerns an existing
        #  SA whose SPI is given in the SPI field, this field indicates the
        #  type of that SA.  For notifications concerning Child SAs, this
        #  field MUST contain either (2) to indicate AH or (3) to indicate
        #  ESP.  Of the notifications defined in this document, the SPI is
        #  included only with INVALID_SELECTORS, REKEY_SA, and
        #  CHILD_SA_NOT_FOUND.  If the SPI field is empty, this field MUST be
        #  sent as zero and MUST be ignored on receipt.
        #  @return [Integer]
        define_field_before :content, :protocol, Types::Int8
        # @!attribute spi_size
        #  8-bit SPI size. Give size of SPI field. Length in octets of the SPI as
        #  defined by the IPsec protocol ID or zero if no SPI is applicable. For a
        #  notification concerning the IKE SA, the SPI Size MUST be zero and
        #  the field must be empty.Set to 0 for an initial IKE SA
        #  negotiation, as SPI is obtained from outer header.
        #  @return [Integer]
        define_field_before :content, :spi_size, Types::Int8, default: 0
        # @!attribute message_type
        #  16-bit notify message type. Specifies the type of notification message.
        #  @return [Integer]
        define_field_before :content, :message_type, Types::Int16Enum, enum: TYPES, default: 0
        # @!attribute spi
        #   the sending entity's SPI. When the {#spi_size} field is zero,
        #   this field is not present in the proposal.
        #   @return [String]
        define_field_before :content, :spi, Types::String,
                            builder: ->(t) { Types::String.new(length_from: t[:spi_size]) }

        alias type message_type

        def initialize(options={})
          if options[:spi] and options[:spi_size].nil?
            options[:spi_size] = options[:spi].size
          end
          super
          self.protocol = options[:protocol] if options[:protocol]
          self.message_type = options[:message_type] if options[:message_type]
          self.type = options[:type] if options[:type]
        end

        # Set protocol
        # @param [Integer,String] value
        # @return [Integer]
        def protocol=(value)
          proto = case value
               when Integer
                 value
               else
                 c = IKE.constants.grep(/PROTO_#{value}/).first
                 c ? IKE.const_get(c) : nil
               end
          raise ArgumentError, "unknown protocol #{value.inspect}" unless proto
          self[:protocol].value = proto
        end

        alias type= message_type=

        # Get protocol name
        # @return [String]
        def human_protocol
          name = IKE.constants.grep(/PROTO/).
                 select { |c| IKE.const_get(c) == protocol }.
                 first || "proto #{protocol}"
          name.to_s.sub(/PROTO_/, '')
        end

        # Get message type name
        # @return [String]
        def human_message_type
          self[:message_type].to_human
        end
        alias human_type human_message_type

        # @return [String]
        def inspect
          str = Inspect.dashed_line(self.class, 2)
          fields.each do |attr|
            next if attr == :body
            if %i(protocol message_type).include? attr
              str << Inspect.shift_level(2)
              str << Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''), attr,
                                          send("human_#{attr}")]
            else
              str << Inspect.inspect_attribute(attr, self[attr], 2)
            end
          end
          str
        end
      end
    end

    self.add_class IKE::Nonce
  end
end
