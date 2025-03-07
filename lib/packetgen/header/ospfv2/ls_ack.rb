# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv2
      # This class handles {OSPFv2 OSPFv2} LS Acknowledgment packets payload.
      # The LS Acknowledgment payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   +-                                                             -+
      #   |                                                               |
      #   +-                      An LSA Header                          -+
      #   |                                                               |
      #   +-                                                             -+
      #   |                                                               |
      #   +-                                                             -+
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                              ...                              |
      # This paylod is implemented as a unique field: {#lsas}, which is an
      # {ArrayOfLSA} object.
      #
      # @example Create a LSAck payload
      #   # standalone
      #   lsack = PacketGen::Header::OSPFv2::LSAck.new
      #   # in a packet
      #   pkt = PacketGen.gen('IP').add('OSPFv2').add('OSPFv2::LSAck')
      #   # access to LSAck payload
      #   lasck = pkt.ospfv2_lsack.class   # => PacketGen::Header::OSPFv2::LSAck
      #
      # @example Adding LSA headers to a LSAck payload
      #   lsack = PacketGen::Header::OSPFv2::LSAck.new
      #   lsack.lsas << { type: 'Router', age: 40, link_state_id: '0.0.0.1', advertising_router: '1.1.1.1', sequence_number: 42, checksum: 0x1234, length: 56 }
      # @author Sylvain Daubert
      class LSAck < Base
        # @!attribute lsas
        #  Array of LSA headers
        #  @return [ArrayOfLSA]
        define_attr :lsas, ArrayOfLSA, builder: ->(_h, t) { t.new(only_headers: true) }
      end
    end

    self.add_class OSPFv2::LSAck
    OSPFv2.bind OSPFv2::LSAck, type: OSPFv2::TYPES['LS_ACK']
  end
end
