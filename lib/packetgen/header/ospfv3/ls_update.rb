# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3
      # This class handles {OSPFv3 OSPFv3} Link State Update packets
      # payload. The LSU payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                            # LSAs                             |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   +-                                                            +-+
      #   |                             LSAs                              |
      #   +-                                                            +-+
      #   |                              ...                              |
      #
      # This paylod is implemented with two fields:
      # * {#lsas_count}, a +BinStruct::Int32+ field,
      # * and {#lsas}, an {ArrayOfLSA} object.
      #
      # @example Create a LSUpdate payload
      #   # standalone
      #   lsu = PacketGen::Header::OSPFv3::LSUpdate.new
      #   # in a packet
      #   pkt = PacketGen.gen('IPv6').add('OSPFv3').add('OSPFv3::LSUpdate')
      #   # make IPv6 header correct for OSPF
      #   pkt.ospfize
      #   # access to LSUpdate payload
      #   lsu = pkt.ospfv3_lsupdate.class    # => PacketGen::Header::OSPFv3::LSUpdate
      #
      # @example Add LSAs to a LSUpdate payload
      #   lsu = PacketGen::Header::OSPFv3::LSUpdate.new
      #   # Adding LSAs with #<< automagically update #lsas_count. To not update it, use #push.
      #   lsu.lsas << { type: 'Router', age: 40, link_state_id: '0.0.0.1', advertising_router: '1.1.1.1', sequence_number: 42 }
      #   lsu.lsas_count     #=> 1
      #   # add a link to Router LSA
      #   lsu.lsas.first.links << { type: 1, metric: 10, interface_id: 1, neighbor_interface_id: 2, neighbor_router_id: '2.2.2.2'}
      # @author Sylvain Daubert
      class LSUpdate < Base
        # @!attribute lsas_count
        #  Count of LSAs included in this update
        #  @return [Integer]
        define_attr :lsas_count, BinStruct::Int32
        # @!attribute lsas
        #  Array of {LSA LSAs}
        #  @return [ArrayOfLSA]
        define_attr :lsas, ArrayOfLSA,
                    builder: ->(h, t) { t.new(counter: h[:lsas_count]) }

        # Calculate checksums of all LSAs
        # @return [void]
        def calc_checksum
          lsas.each(&:calc_checksum)
        end

        # Calculate length of all LSAs
        def calc_length
          lsas.each(&:calc_length)
        end
      end
    end

    self.add_class OSPFv3::LSUpdate
    OSPFv3.bind OSPFv3::LSUpdate, type: OSPFv3::TYPES['LS_UPDATE']
  end
end
