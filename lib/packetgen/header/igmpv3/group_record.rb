# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class IGMPv3
      # Class to handle IGMPv3 Group Records.
      #
      # A Group Record is a block of attributes.containing information
      # pertaining to the sender's membership in a single multicast group on
      # the interface from which the Report is sent.
      #
      # A Group Record has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       Multicast Address                       |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       Source Address [1]                      |
      #   +-                                                             -+
      #   |                       Source Address [2]                      |
      #   +-                                                             -+
      #   .                               .                               .
      #   .                               .                               .
      #   .                               .                               .
      #   +-                                                             -+
      #   |                       Source Address [N]                      |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   .                                                               .
      #   .                         Auxiliary Data                        .
      #   .                                                               .
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class GroupRecord < BinStruct::Struct
        include BinStruct::Structable

        # Known record types
        RECORD_TYPES = {
          'MODE_IS_INCLUDE' => 1,
          'MODE_IS_EXCLUDE' => 2,
          'CHANGE_TO_INCLUDE_MODE' => 3,
          'CHANGE_TO_EXCLUDE_MODE' => 4,
          'ALLOW_NEW_SOURCES' => 5,
          'BLOCK_OLD_SOURCES' => 6
        }.freeze

        # @!attribute type
        #  8-bit record type
        #  @return [Integer]
        define_attr :type, BinStruct::Int8Enum, enum: RECORD_TYPES
        # @!attribute aux_data_len
        #  8-bit length of of the Auxiliary Data field ({#aux_data}), in unit of
        #  32-bit words
        #  @return [Integer]
        define_attr :aux_data_len, BinStruct::Int8, default: 0
        # @!attribute number_of_sources
        #  16-bit Number of source addresses in {#source_addr}
        #  @return [Integer]
        define_attr :number_of_sources, BinStruct::Int16, default: 0
        # @!attribute multicast_addr
        #  IP multicast address to which this Group Record pertains
        #  @return [IP::Addr]
        define_attr :multicast_addr, IP::Addr, default: '0.0.0.0'
        # @!attribute source_addr
        #  Array of source addresses
        #  @return [IP::ArrayOfAddr]
        define_attr :source_addr, IP::ArrayOfAddr,
                    builder: ->(h, t) { t.new(counter: h[:number_of_sources]) }
        # @!attribute aux_data
        #  @return [String]
        define_attr :aux_data, BinStruct::String,
                    builder: ->(h, t) { t.new(length_from: -> { h[:aux_data_len].to_i * 4 }) }

        def human_type
          self[:type].to_human
        end

        def to_human
          "#{human_type}(ma:#{multicast_addr}|src:#{source_addr.to_human})"
        end
      end

      # Class to handle series of {GroupRecord}.
      # @author Sylvain Daubert
      class GroupRecords < BinStruct::Array
        set_of GroupRecord

        # Separator used in +#to_human+.
        HUMAN_SEPARATOR = ';'
      end
    end
  end
end
