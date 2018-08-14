# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class IGMPv3
      # Class to handle IGMPv3 Group Records.
      #
      # A Group Record is a block of fields containing information
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
      class GroupRecord < Types::Fields
        # Known record types
        RECORD_TYPES = {
          'MODE_IS_INCLUDE'        => 1,
          'MODE_IS_EXCLUDE'        => 2,
          'CHANGE_TO_INCLUDE_MODE' => 3,
          'CHANGE_TO_EXCLUDE_MODE' => 4,
          'ALLOW_NEW_SOURCES'      => 5,
          'BLOCK_OLD_SOURCES'      => 6
        }.freeze

        # @!attribute type
        #  8-bit record type
        #  @return [Integer]
        define_field :type, Types::Int8Enum, enum: RECORD_TYPES
        # @!attribute aux_data_len
        #  8-bit length of of the Auxiliary Data field ({#aux_data}), in unit of
        #  32-bit words
        #  @return [Integer]
        define_field :aux_data_len, Types::Int8, default: 0
        # @!attribute number_of_sources
        #  16-bit Number of source addresses in {#source_addr}
        #  @return [Integer]
        define_field :number_of_sources, Types::Int16, default: 0
        # @!attribute multicast_addr
        #  IP multicast address to which this Group Record pertains
        #  @return [IP::Addr]
        define_field :multicast_addr, IP::Addr, default: '0.0.0.0'
        # @!attribute source_addr
        #  Array of source addresses
        #  @return [IP::ArrayOfAddr]
        define_field :source_addr, IP::ArrayOfAddr,
                     builder: ->(h, t) { t.new(counter: h[:number_of_sources]) }
        # @!attribute aux_data
        #  @return [String]
        define_field :aux_data, Types::String,
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
      class GroupRecords < Types::Array
        set_of GroupRecord

        # Separator used in {#to_human}.
        HUMAN_SEPARATOR = ';'
      end
    end
  end
end
