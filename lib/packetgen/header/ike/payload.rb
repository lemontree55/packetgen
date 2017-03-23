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
        # @!attribute content
        #  Payload content, for unknown payload types. Known payloads do not own
        #  this attribute, as their content is defined through fields.
        #  @return [String]
        define_field :content, Types::String

        # Defining a body permits using Packet#parse to parse next IKE payloads.
        define_field :body, Types::String

        # @!attribute critical
        #  critical flag
        #  @return [Boolean]
        define_bit_fields_on :flags, :critical, :reserved, 7

        # @private
        alias base_read read

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          base_read str
          unless self[:content].nil?
            content_length = length - self.class.new.sz
            if content_length > 0
              self[:body] = self[:content][content_length..-1]
              self[:content] = self[:content][0, content_length]
            end
          end
          self
        end
      end
    end

    self.add_class IKE::Payload
  end
end

# here, future payloads to be required
require_relative 'sa'

module PacketGen
  module Header
    IKE.bind_header IKE::SA, next: 33
    IKE::Payload.bind_header IKE::SA, next: 33
    IKE::SA.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::Payload.bind_header IKE::Payload, next: ->(v) { v > 0 }
  end
end
