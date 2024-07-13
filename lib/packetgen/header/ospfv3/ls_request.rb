# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3
      # This class handle LSA requests, as used in {LSRequest} payloads.
      # The LSA request payload has the following format:
      #   0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |              0                |        LS Type                |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                         Link State ID                         |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                       Advertising Router                      |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #
      # It is composed of:
      # * a 16-bit {#reserved} field,
      # * a 16-bit {#type} field,
      # * a 32-bit {#link_state_id} field,
      # * and a 32-bit {#advertising_router} field.
      # @author Sylvain Daubert
      class LSR < Types::Fields
        include Types::Fieldable

        # @!attribute reserved
        #  reserved field.
        #  @return [Integer]
        define_field :reserved, Types::Int16, default: 0
        # @!attribute type
        #  The type of the LSA to request.
        #  @return [Integer]
        define_field :type, Types::Int16Enum, enum: LSAHeader::TYPES
        # @!attribute link_state_id
        #  This field identifies the portion of the internet environment
        #  that is being described by the LSA to request.
        #  @return [String]
        define_field :link_state_id, IP::Addr
        # @!attribute advertising_router
        #  The Router ID of the requested LSA.
        #  @return [String]
        define_field :advertising_router, IP::Addr

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

      # This class defines a specialized {Types::Array array} to handle series
      # of {LSR LSRs}.
      # @author Sylvain Daubert
      class ArrayOfLSR < Types::Array
        set_of LSR
      end

      # This class handles {OSPFv3 OSPFv3} Link State Request packets
      # payload. The LSR payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |              0                |        LS Type                |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       Link State ID                           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                     Advertising Router                        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                              ...                              |
      #
      # This paylod is implemented as a unique field: {#lsrs}, which is an
      # {ArrayOfLSR} object.
      #
      # == Create a LSRequest payload
      #   # standalone
      #   lsr = PacketGen::Header::OSPFv3::LSRequest.new
      #   # in a packet
      #   pkt = PacketGen.gen('IPv6', src: source_ip).add('OSPFv3').add('OSPFv3::LSRequest')
      #   # make IPv6 header correct for OSPF
      #   pkt.ospfize
      #   # access to LSRequest payload
      #   pkt.ospfv3_lsrequest    # => PacketGen::Header::OSPFv3::LSRequest
      #
      # == Add LSA requests to a LSRequest
      #   lsr.lsrs << { type: 'Router', link_state_id: '0.0.0.1', advertising_router: '1.1.1.1'}
      # @author Sylvain Daubert
      class LSRequest < Base
        # @!attribute lsrs
        #  Array of {LSR}
        #  @return [ArrayOfLSR]
        define_field :lsrs, ArrayOfLSR
      end
    end

    self.add_class OSPFv3::LSRequest
    OSPFv3.bind OSPFv3::LSRequest, type: OSPFv3::TYPES['LS_REQUEST']
  end
end
