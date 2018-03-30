# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3

      # This class handles {OSPFv3 OSPFv3} DB description packets payload.
      # The DB description payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
      #   |       0       |               Options                          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
      #   |        Interface MTU          |      0        |0|0|0|0|0|I|M|MS|
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
      #   |                     DD sequence number                         |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
      #   |                                                                |
      #   +-                                                              -+
      #   |                                                                |
      #   +-                      An LSA Header                           -+
      #   |                                                                |
      #   +-                                                              -+
      #   |                                                                |
      #   +-                                                              -+
      #   |                                                                |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
      #   |                              ...                               |
      # @author Sylvain Daubert
      class DbDescription < Base

        # @!attribute mtu
        #  8-bit zero field before {#options} one
        #  @return [Integer]
        define_field :zero, Types::Int8, default: 0

        # @!macro define_options
        OSPFv3.define_options(self)

        # @!attribute mtu
        #  16-bit interface MTU
        #  @return [Integer]
        define_field :mtu, Types::Int16
        # @!attribute flags
        #  16-bit interface flags ({#i_flag}, {#m_flag} and {#ms_flag})
        #  @return [Integer]
        define_field :flags, Types::Int16
        # @!attribute i_flag
        #  Init bit
        #  @return [Boolean]
        # @!attribute m_flag
        #  More bit
        #  @return [Boolean]
        # @!attribute ms_flag
        #  Master/Slave bit
        #  @return [Boolean]
        define_bit_fields_on :flags, :zz, 13, :i_flag, :m_flag, :ms_flag

        # @!attribute sequence_number
        #  32-bit DD sequence number, used to sequence the collection of Database
        #  Description Packets.
        #  @return [Integer]
        define_field :sequence_number, Types::Int32
        alias seqnum sequence_number
        alias seqnum= sequence_number=
        
        # @!attribute lsas
        #  Array of LSA headers
        #  @return [ArrayOfLSAHeader]
        define_field :lsas, ArrayOfLSAHeader
      end
    end

    self.add_class OSPFv3::DbDescription
    OSPFv3.bind_header OSPFv3::DbDescription, type: OSPFv3::TYPES['DB_DESCRIPTION']
  end
end
