# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv2
      # This class handle a LS request, which is composed 3 +BinStruct::Int32+ fields:
      # * {#type},
      # * {#link_state_id},
      # * and {#advertising_router}.
      # @author Sylvain Daubert
      class LSR < BinStruct::Struct
        include BinStruct::Structable

        # @!attribute type
        #  The type of the LSA to request.
        #  @return [Integer]
        define_attr :type, BinStruct::Int32Enum, enum: LSAHeader::TYPES
        # @!attribute link_state_id
        #  This field identifies the portion of the internet environment
        #  that is being described by the LSA to request.
        #  @return [String]
        define_attr :link_state_id, IP::Addr
        # @!attribute advertising_router
        #  The Router ID of the requested LSA.
        #  @return [String]
        define_attr :advertising_router, IP::Addr

        # Get human-readable type
        # @return [String]
        def human_type
          self[:type].to_human
        end

        # @return [String]
        def to_human
          "LSR<#{human_type},#{link_state_id},#{advertising_router}>"
        end
      end

      # This class defines a specialized +BinStruct::Array+ to handle series
      # of {LSR LSRs}.
      # @author Sylvain Daubert
      class ArrayOfLSR < BinStruct::Array
        set_of LSR
      end

      # This class handles {OSPFv2 OSPFv2} Link State Request packets
      # payload. The LSR payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                          LS type                              |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       Link State ID                           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                     Advertising Router                        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                              ...                              |
      # This paylod is implemented as a unique field: {#lsrs}, which is an
      # {ArrayOfLSR} object.
      #
      # @example Create a LSRequest payload
      #   # standalone
      #   lsr = PacketGen::Header::OSPFv2::LSRequest.new
      #   # in a packet
      #   pkt = PacketGen.gen('IP').add('OSPFv2').add('OSPFv2::LSRequest')
      #   # make IP header correct for OSPF
      #   pkt.ospfize
      #   # access to LSRequest payload
      #   pkt.ospfv2_lsrequest.class    # => PacketGen::Header::OSPFv2::LSRequest
      #
      # @example Add LSA requests to a LSRequest
      #   lsr = PacketGen::Header::OSPFv2::LSRequest.new
      #   lsr.lsrs << { type: 'Router', link_state_id: '0.0.0.1', advertising_router: '1.1.1.1'}
      # @author Sylvain Daubert
      class LSRequest < Base
        # @!attribute lsrs
        #  Array of {LSR}
        #  @return [ArrayOfLSR]
        define_attr :lsrs, ArrayOfLSR
      end
    end

    self.add_class OSPFv2::LSRequest
    OSPFv2.bind OSPFv2::LSRequest, type: OSPFv2::TYPES['LS_REQUEST']
  end
end
