module PacketGen
  module Header
    class IKE

      # Base class for IKE payloads. This class may also be used for unknown payloads.
      # @author Sylvain Daubert
      class Payload < Base
        # @!attribute next
        #  8-bit next payload
        #  @return [Integer]
        define_field :next, Types::Int8
        # @!attribute flags
        #  8-bit flags
        #  @return [Integer]
        define_field :flags, Types::Int8
        # @!attribute length
        #  16-bit payload total length, including generic payload header
        #  @return [Integer]
        define_field :length, Types::Int16

        # Defining a body permits using Packet#parse to parse next IKE payloads.
        define_field :body, Types::String

        # @!attribute critical
        #  critical flag
        #  @return [Boolean]
        define_bit_fields_on :flags, :critical, :reserved, 7
      end
    end

    self.add_class IKE::Payload
  end
end

module PacketGen
  module Header
    IKE.bind_header IKE::Payload
  end
end
