# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    module MLDv2
      # Class to handle MLDv2 Mcast Address Records (MAR).
      #
      # A Mcast Address Record has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   *                                                               *
      #   |                                                               |
      #   *                       Multicast Address                       *
      #   |                                                               |
      #   *                                                               *
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   *                                                               *
      #   |                                                               |
      #   *                       Source Address [1]                      *
      #   |                                                               |
      #   *                                                               *
      #   |                                                               |
      #   +-                                                             -+
      #   .                               .                               .
      #   .                               .                               .
      #   .                               .                               .
      #   +-                                                             -+
      #   |                                                               |
      #   *                                                               *
      #   |                                                               |
      #   *                       Source Address [N]                      *
      #   |                                                               |
      #   *                                                               *
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   .                                                               .
      #   .                         Auxiliary Data                        .
      #   .                                                               .
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class McastAddressRecord < Types::Fields
        include Types::Fieldable

        # Known record types
        RECORD_TYPES = IGMPv3::GroupRecord::RECORD_TYPES

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
        #  IP multicast address to which this Multicast Address Record pertains
        #  @return [IPv6::Addr]
        define_field :multicast_addr, IPv6::Addr, default: '::'
        # @!attribute source_addr
        #  Array of source addresses
        #  @return [IPv6::ArrayOfAddr]
        define_field :source_addr, IPv6::ArrayOfAddr,
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

      # Class to handle series of {McastAddressRecord}.
      # @author Sylvain Daubert
      class McastAddressRecords < Types::Array
        set_of McastAddressRecord

        # Separator used in {#to_human}.
        HUMAN_SEPARATOR = ';'
      end
    end
  end
end
