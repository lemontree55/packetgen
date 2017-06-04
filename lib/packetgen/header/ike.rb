module PacketGen
  module Header

    # This class handles a pseudo-header used to differentiate ESP from IKE headers
    # in a UDP datagram with port 4500.
    # @author Sylvain Daubert
    class NonESPMarker < Base
      # @!attribute non_esp_marker
      #  32-bit zero marker to differentiate IKE packet over UDP port 4500 from ESP ones
      #  @return [Integer]
      define_field :non_esp_marker, Types::Int32, default: 0
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

      # Check non_esp_marker field
      # @see [Base#parse?]
      def parse?
        non_esp_marker == 0
      end
    end

    # IKE is the Internet Key Exchange protocol (RFC 7296). Ony IKEv2 is supported.
    #
    # A IKE header consists of a header, and a set of payloads. This class
    # handles IKE header. For payloads, see {IKE::Payload}.
    #
    # == IKE header
    # The format of a IKE header is shown below:
    #                       1                   2                   3
    #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                       IKE SA Initiator's SPI                  |
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                       IKE SA Responder's SPI                  |
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                          Message ID                           |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                            Length                             |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # A IKE header consists of:
    # * a IKE SA initiator SPI ({#init_spi}, {Types::Int64} type),
    # * a IKE SA responder SPI ({#resp_spi}, {Types::Int64} type),
    # * a Next Payload field ({#next}, {Types::Int8} type),
    # * a Version field ({#version}, {Types::Int8} type, with first 4-bit field
    #   as major number, and last 4-bit field as minor number),
    # * a Exchange type ({#exchange_type}, {Types::Int8} type),
    # * a {#flags} field ({Types::Int8} type),
    # * a Message ID ({#message_id}, {Types::Int32} type),
    # * and a {#length} ({Types::Int32} type).
    #
    # == Create a IKE header
    # === Standalone
    #   ike = PacketGen::Header::IKE.new
    # === Classical IKE packet
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE')
    #   # access to IKE header
    #   pkt.ike    # => PacketGen::Header::IKE
    # === NAT-T IKE packet
    #   # NonESPMarker is used to insert a 32-bit null field between UDP header
    #   # and IKE one to differentiate it from ESP-in-UDP (see RFC 3948)
    #   pkt = PacketGen.gen('IP').add('UDP').add('NonESPMarker').add('IKE)
    # @author Sylvain Daubert
    class IKE < Base

      # Classical well-known UDP port for IKE
      UDP_PORT1 = 500
      # Well-known UDP port for IKE when NAT is detected
      UDP_PORT2 = 4500

      PROTO_IKE = 1
      PROTO_AH  = 2
      PROTO_ESP = 3

      TYPE_IKE_SA_INIT     = 34
      TYPE_IKE_AUTH        = 35
      TYPE_CREATE_CHILD_SA = 36
      TYPE_INFORMATIONAL   = 37

      # @!attribute init_spi
      #  64-bit initiator SPI
      #  @return [Integer]
      define_field :init_spi, Types::Int64 
      # @!attribute resp_spi
      #  64-bit responder SPI
      #  @return [Integer]
      define_field :resp_spi, Types::Int64 
      # @!attribute next
      #  8-bit next payload type
      #  @return [Integer]
      define_field :next, Types::Int8
      # @!attribute version
      #  8-bit IKE version
      #  @return [Integer]
      define_field :version, Types::Int8, default: 0x20
      # @!attribute [r] exchange_type
      #  8-bit exchange type
      #  @return [Integer]
      define_field :exchange_type, Types::Int8
      # @!attribute flags
      #  8-bit flags
      #  @return [Integer]
      define_field :flags, Types::Int8
      # @!attribute message_id
      #  32-bit message ID
      #  @return [Integer]
      define_field :message_id, Types::Int32
      # @!attribute length
      #  32-bit length of total message (header + payloads)
      #  @return [Integer]
      define_field :length, Types::Int32

      # Defining a body permits using Packet#parse to parse IKE payloads.
      # But this method is hidden as prefered way to access payloads is via #payloads
      define_field :body, Types::String

      # @!attribute mjver
      #  4-bit major version value
      #  @return [Integer]
      # @!attribute mnver
      #  4-bit minor version value
      #  @return [Integer]
      define_bit_fields_on :version, :mjver, 4, :mnver, 4

      # @!attribute rsv1
      #  @return [Integer]
      # @!attribute rsv2
      #  @return [Integer]
      # @!attribute flag_i
      #  bit set in message sent by the original initiator
      #  @return [Boolean]
      # @!attribute flag_r
      #  indicate this message is a response to a message containing the same Message ID
      #  @return [Boolean]
      # @!attribute flag_v
      #  version flag. Ignored by IKEv2 peers, and should be set to 0
      #  @return [Boolean]
      define_bit_fields_on :flags, :rsv1, 2, :flag_r, :flag_v, :flag_i, :rsv2, 3

      # @param [Hash] options
      # @see Base#initialize
      def initialize(options={})
        super
        calc_length unless options[:length]
        self.type = options[:type] if options[:type]
        self.type = options[:exchange_type] if options[:exchange_type]
      end

        # Set exchange type
        # @param [Integer,String] value
        # @return [Integer]
      def exchange_type=(value)
        type = case value
               when Integer
                 value
               else
                 c = self.class.constants.grep(/TYPE_#{value}/).first
                 c ? self.class.const_get(c) : nil
               end
        raise ArgumentError, "unknown exchange type #{value.inspect}" unless type
        self[:exchange_type].value = type
      end
      alias type exchange_type
      alias type= exchange_type=

      # Get exchange type name
      # @return [String
      def human_exchange_type
          name = self.class.constants.grep(/TYPE_/).
                 select { |c| self.class.const_get(c) == type }.
                 first || "type #{type}"
          name.to_s.sub(/TYPE_/, '')
      end
      alias human_type human_exchange_type

      # Calculate length field
      # @return [Integer]
      def calc_length
        self[:length].value = self.sz
      end

      # IKE payloads
      # @return [Array<Payload>]
      def payloads
        payloads = []
        body = self.body
        while body.is_a?(Payload) do
          payloads << body
          body = body.body
        end
        payloads
      end

      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        to_h.each do |attr, value|
          next if attr == :body
          case attr
          when :flags
            str_flags = ''
            %w(r v i).each do |flag|
              str_flags << (send("flag_#{flag}?") ? flag.upcase : '.')
            end
            str << Inspect.shift_level(2)
            str << Inspect::FMT_ATTR % [value.class.to_s.sub(/.*::/, ''), attr,
                                        str_flags]
          when :exchange_type
            str << Inspect.shift_level(2)
            str << Inspect::FMT_ATTR % [value.class.to_s.sub(/.*::/, ''), attr,
                                        human_exchange_type]
          else
            str << Inspect.inspect_attribute(attr, value, 2)
          end
        end
        str
      end
    end

    self.add_class IKE
    self.add_class NonESPMarker

    UDP.bind_header IKE, dport: IKE::UDP_PORT1, sport: IKE::UDP_PORT1
    UDP.bind_header NonESPMarker, dport: IKE::UDP_PORT2, sport: IKE::UDP_PORT2
    NonESPMarker.bind_header IKE
  end
end

require_relative 'ike/payload'
