module PacketGen
  module Header

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
    # * a {#length} ({Types::Int32} type),
    # * and a {#body}, containing IKE payloads.
    # For IKE packets transported over UDP port 4500, IKE header is prepended with a
    # 32-bit field set to 0 ({#non_esp_marker}, type {Types::Int32}).
    #
    # == Create a IKE header
    #   # standalone
    #   ike = PacketGen::Header::IKE.new
    #   # in a packet
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE')
    #   # access to IKE header
    #   pkt.ike    # => PacketGen::Header::IKE
    # @author Sylvain Daubert
    class IKE < Base

      # Classical well-known UDP port for IKE
      UDP_PORT1 = 500
      # Well-known UDP port for IKE when NAT is detected
      UDP_PORT2 = 4500

      # @!attribute non_esp_marker
      #  32-bit zero marker to differentiate IKE packet over UDP port 4500 from ESP ones
      #  @return [Integer]
      define_field :non_esp_marker, Types::Int32, default: 0
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
      # @!attribute exchange_type
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
    end

    self.add_class IKE

    UDP.bind_header IKE, dport: IKE::UDP_PORT1, sport: IKE::UDP_PORT1
    UDP.bind_header IKE, dport: IKE::UDP_PORT2, sport: IKE::UDP_PORT2
  end
end
