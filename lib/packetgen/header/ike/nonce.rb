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
      #
      # == Create a Nonce payload
      #   # Create a IKE packet with a Nonce payload
      #   pkt = PacketGen.gen('IP').add('UDP').add('IKE')
      #   pkt.add('Nonce', data: "abcdefgh")
      # @author Sylvain Daubert
      class Nonce < Payload

        # Payload type number
        PAYLOAD_TYPE = 40
      end
    end

    self.add_class IKE::Nonce
  end
end
