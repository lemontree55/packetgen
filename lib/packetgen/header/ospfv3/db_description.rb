# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
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
      #
      # A DB description payload is composed of:
      # * a 8-bit {#reserved} field (+BinStruct::Int8+),
      # * a 24-bit {#options} field (+BinStruct::Int24+),
      # * a 16-bit {#mtu} field (+BinStruct::Int16+),
      # * a 16-bit {#flags} field (+BinStruct::Int16+). Supported flags are:
      #   * {i_flag},
      #   * {m_flag},
      #   * {ms_flag},
      # * a 32-bit {#sequence_number} field (+BinStruct::Int32+),
      # * and an array of {LSAHeader LSAHeaders} ({#lsas}, {ArrayOfLSA}).
      #
      # @example Create a DbDescription payload
      #   # standalone
      #   dbd = PacketGen::Header::OSPFv3::DbDescription.new
      #   # in a packet
      #   pkt = PacketGen.gen('IPv6').add('OSPFv3').add('OSPFv3::DbDescription')
      #   # access to DbDescription payload
      #   pkt.ospfv3_dbdescription.class    # => PacketGen::Header::OSPFv3::DbDescription
      #
      # @example DbDescription attributes
      #   dbd = PacketGen::Header::OSPFv3::DbDescription.new
      #   dbd.reserved = 0
      #   # set options. Options may also be set one by one with #v6_opt, #e_opt,
      #   # #n_opt, #r_opt and #dc_opt
      #   dbd.options = 0x33
      #   dbd.mtu = 1500
      #   dbd.flags = 0
      #   dbd.seqnum = 0x800001
      #   # add a LSA Router header
      #   dbd.lsas << { type: 'Router', age: 40, link_state_id: '0.0.0.1', advertising_router: '1.1.1.1', sequence_number: 42, checksum: 0x1234, length: 56 }
      # @author Sylvain Daubert
      class DbDescription < Base
        # @!attribute reserved
        #  8-bit zero field before {#options} one
        #  @return [Integer]
        define_attr :reserved, BinStruct::Int8, default: 0

        # @!macro define_ospfv3_options
        OSPFv3.define_options(self)

        # @!attribute mtu
        #  16-bit interface MTU
        #  @return [Integer]
        define_attr :mtu, BinStruct::Int16
        # @!attribute flags
        #  16-bit interface flags ({#i_flag}, {#m_flag} and {#ms_flag})
        #  @return [Integer]
        # @!attribute i_flag
        #  Init bit from {#flags} field
        #  @return [Integer]
        # @!attribute m_flag
        #  More bit from {#flags} field
        #  @return [Integer]
        # @!attribute ms_flag
        #  Master/Slave bit from {#flags} field
        #  @return [Integer]
        define_bit_attr :flags, zz: 13, i_flag: 1, m_flag: 1, ms_flag: 1

        # @!attribute sequence_number
        #  32-bit DD sequence number, used to sequence the collection of Database
        #  Description Packets.
        #  @return [Integer]
        define_attr :sequence_number, BinStruct::Int32
        alias seqnum sequence_number
        alias seqnum= sequence_number=

        # @!attribute lsas
        #  Array of LSA headers
        #  @return [ArrayOfLSA]
        define_attr :lsas, ArrayOfLSA, builder: ->(_h, t) { t.new(only_headers: true) }
      end
    end

    self.add_class OSPFv3::DbDescription
    OSPFv3.bind OSPFv3::DbDescription, type: OSPFv3::TYPES['DB_DESCRIPTION']
  end
end
