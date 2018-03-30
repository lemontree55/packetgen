# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3

      # This class handle a LS request, which is composed of:
      # * a 16-bit zero field,
      # * a 16-bit {#type} field,
      # * a 32-bit {#link_state_id} field,
      # * and a 32-bit {#advertising_router} field.
      # @author Sylvain Daubert
      class LSR < Types::Fields
        # @!attribute zero
        #  zero field.
        #  @return [Integer]
        define_field :type, Types::Int16, default: 0
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
      # This paylod is implemented as a unique field: {#lsrs}, which is an
      # {ArrayOfLSR} object.
      # @author Sylvain Daubert
      class LSRequest < Base
        # @!attribute lsrs
        #  Array of {LSR}
        #  @return [ArrayOfLSR]
        define_field :lsrs, ArrayOfLSR
      end
    end

    self.add_class OSPFv3::LSRequest
    OSPFv3.bind_header OSPFv3::LSRequest, type: OSPFv3::TYPES['LS_REQUEST']
  end
end
