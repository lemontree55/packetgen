# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3

      # This class handles {OSPFv3 OSPFv3} Link State Acknownledgment packets
      # payload. The LSAck payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   +-                                                            +-+
      #   |                             LSAs                              |
      #   +-                                                            +-+
      #   |                              ...                              |
      #
      # This paylod is implemented with only one field:
      # * {#lsas}, an {ArrayOfLSA} object.
      #
      # == Create a LSAck payload
      #   # standalone
      #   lsack = PacketGen::Header::OSPFv3::LSAck.new
      #   # in a packet
      #   pkt = PacketGen.gen('IPv6', src: source_ip).add('OSPFv3').add('OSPFv3::LSAck')
      #   # access to LSAck payload
      #   lasck = pkt.ospfv3_lsack    # => PacketGen::Header::OSPFv3::LSAck
      #
      # == Adding LSA headers to a LSAck payload
      #   lsack.lsas << { type: 'Router', age: 40, link_state_id: '0.0.0.1', advertising_router: '1.1.1.1', sequence_number: 42, checksum: 0x1234, length: 56 }
      #   # a header may also be set from an existing lsa
      #   lasck.lsas << existing_lsa.to_lsa_header
      # @author Sylvain Daubert
      class LSAck < Base
        # @!attribute lsas
        #  Array of {LSA LSAs}
        #  @return [ArrayOfLSA]
        define_field :lsas, ArrayOfLSA,
                     builder: ->(h, t) { t.new(only_headers: true) }
      end
    end

    self.add_class OSPFv3::LSAck
    OSPFv3.bind_header OSPFv3::LSAck, type: OSPFv3::TYPES['LS_ACK']
  end
end
