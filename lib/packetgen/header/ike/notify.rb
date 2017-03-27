# coding: utf-8
module PacketGen
  module Header
    class IKE

      # This class handles Notify payloads, as defined in RFC 7296 §3.10.
      #
      # A Notify payload contains a generic payload header (see {Payload}) and
      # datasom specific fields:
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
      # * {#data} (type {Types::String}).
      # @author Sylvain Daubert
      class Notify < Payload

        # Payload type number
        PAYLOAD_TYPE = 41

        # Unsupported critical payload
        TYPE_UNSUPPORTED_CRITICAL_PAYLOAD = 1
        # Invalid IKE SPI
        TYPE_INVALID_IKE_SPI = 4
        # Invalid major version
        TYPE_INVALID_MAJOR_VERSION = 5
        # Invalid syntax
        TYPE_INVALID_SYNTAX = 7
        # Invalid message ID
        TYPE_INVALID_MESSAGE_ID = 9
        # Invalid SPI
        TYPE_INVALID_SPI = 11
        # No proposal chosen (none of the proposed crypto suites was acceptable)
        TYPE_NO_PROPOSAL_CHOSEN = 14
        # Invalid KE payload
        TYPE_INVALID_KE_PAYLOAD = 17
        # Authentication failed
        TYPE_AUTHENTICATION_FAILED = 24
        # Single pair required
        TYPE_SINGLE_PAIR_REQUIRED = 34
        # No additional SAs
        TYPE_NO_ADDITIONAL_SAS = 35
        # Internal address failture
        TYPE_INTERNAL_ADDRESS_FAILURE = 36
        # Failed CP required
        TYPE_FAILED_CP_REQUIRED = 37
        # traffic selectors unacceptable
        TYPE_TS_UNACCEPTABLE  = 38
        # invalid selectors
        TYPE_INVALID_SELECTORS = 39
        # Temporary failure
        TYPE_TEMPORARY_FAILURE = 43
        # Child SA not found
        TYPE_CHILD_SA_NOT_FOUND = 44
        # Initial contact
        TYPE_INITIAL_CONTACT = 16384
        # Set window size
        TYPE_SET_WINDOW_SIZE = 16385
        # Additional traffic selector possible
        TYPE_ADDITIONAL_TS_POSSIBLE = 16386
        # IPcomp supported
        TYPE_IPCOMP_SUPPORTED = 16387
        # NAT detection source IP
        TYPE_NAT_DETECTION_SOURCE_IP = 16388
        # NAT detection destination IP
        TYPE_NAT_DETECTION_DESTINATION_IP = 16389
        # Cookie
        TYPE_COOKIE = 16390
        # Use transport mode (tunnel mode is default)
        TYPE_USE_TRANSPORT_MODE = 16391
        # HTTP certificate look up supported
        TYPE_HTTP_CERT_LOOKUP_SUPPORTED = 16392
        # Rekey SA
        TYPE_REKEY_SA = 16393
        # ESP TFC paddin not supported
        TYPE_ESP_TFC_PADDING_NOT_SUPPORTED = 16394
        # Non-first fragment also
        TYPE_NON_FIRST_FRAGMENTS_ALSO = 16395

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
        define_field_before :content, :message_type, Types::Int16
        # @!attribute spi
        #   the sending entity's SPI. When the {#spi_size} field is zero,
        #   this field is not present in the proposal.
        #   @return [String]
        define_field_before :content, :spi, Types::String,
                            builder: ->(t) { Types::String.new('', length_from: t[:spi_size]) }

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

        # Set message type
        # @param [Integer,String] value
        # @return [Integer]
        def message_type=(value)
          type = case value
               when Integer
                 value
               else
                 c = self.class.constants.grep(/TYPE_#{value}/).first
                 c ? self.class.const_get(c) : nil
               end
          raise ArgumentError, "unknown message type #{value.inspect}" unless type
          self[:message_type].value = type
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
          name = self.class.constants.grep(/TYPE_/).
                 select { |c| self.class.const_get(c) == type }.
                 first || "type #{type}"
          name.to_s.sub(/TYPE_/, '')
        end
        alias human_type human_message_type

        # @return [String]
        def inspect
          str = Inspect.dashed_line(self.class, 2)
          @fields.each do |attr, value|
            next if attr == :body
            if %i(protocol message_type).include? attr
              str << Inspect.shift_level(2)
              str << Inspect::FMT_ATTR % [value.class.to_s.sub(/.*::/, ''), attr,
                                          send("human_#{attr}")]
            else
              str << Inspect.inspect_attribute(attr, value, 2)
            end
          end
          str
        end
      end
    end

    self.add_class IKE::Nonce
  end
end
