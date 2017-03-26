# coding: utf-8
module PacketGen
  module Header
    class IKE

      # This class handles Nonce payloads, as defined in RFC 7296 §3.9.
      #
      # A Nonce payload contains a generic payload header (see {Payload}) and
      # data field (type {Types::String}):
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                            Nonce Data                         ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class Nonce < Payload
        delete_field :content
        # @!attribute data
        #  Key Exchange data
        #  @return [String]
        define_field_before :body, :data, Types::String

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          super
          hlen = self.class.new.sz
          plen = length - hlen
          data.read str[hlen, plen]
          body.read str[hlen+plen..-1]
          self
        end
      end
    end

    self.add_class IKE::Nonce
  end
end
