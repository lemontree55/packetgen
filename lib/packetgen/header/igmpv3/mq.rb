# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class IGMPv3
      # IGMPv3 Membership Query.
      #
      # This is a subpayload for IGMPv3 packets only. This kind of payload is
      # sent by IP multicast routers to query the multicast reception state of
      # neighboring interfaces. Queries has following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         Group Address                         |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       Source Address [1]                      |
      #   +-                                                             -+
      #   |                       Source Address [2]                      |
      #   +-                              .                              -+
      #   .                               .                               .
      #   .                               .                               .
      #   +-                                                             -+
      #   |                       Source Address [N]                      |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #
      # Struct are:
      # * 32-bit {#group_addr} field ({Header::IP::Addr} type),
      # * 4-bit {#resv}, a reserved field,
      # * 1-bit {#flag_s} (Suppress Router-Side Processing),
      # * 3-bit {#qrv} (Querier's Robustness Variable),
      # * 8-bit {#qqic} (Querier's Query Interval Code),
      # * 16-bit {#number_of_sources},
      # * {#source_addr} field, a {IP::ArrayOfAddr} to handle sources addresses.
      # @author Sylvain Daubert
      class MQ < Base
        # @!attribute group_addr
        #  IP Group address
        #  @return [IP::Addr]
        define_attr :group_addr, IP::Addr, default: '0.0.0.0'
        # @!attribute u8
        #  First 8-bit field, composed of {#resv}, {#flag_s} and {#qrv}
        #  @return [Integer]
        # @!attribute resv
        #  4-bit reserved field
        #  @return [Integer]
        # @!attribute flag_s
        #  1-bit S flag (Suppress Router-Side Processing)
        #  @return [Integer]
        # @!attribute qrv
        #  3-bit Querier's Robustness Variable
        #  @return [Integer]
        define_bit_attr :u8, resv: 4, flag_s: 1, qrv: 3
        # @!attribute qqic
        #  8-bit QQIC
        #  @return [Integer,Float]
        define_attr :qqic, BinStruct::Int8
        # @!attribute number_of_sources
        #  16-bit Number of Sources in {#source_addr}
        #  @return [Integer]
        define_attr :number_of_sources, BinStruct::Int16

        # @!attribute source_addr
        #  Array of IP source addresses
        #  @return [IP::ArrayOfAddr]
        define_attr :source_addr, IP::ArrayOfAddr,
                    builder: ->(h, t) { t.new(counter: h[:number_of_sources]) }

        undef qqic, qqic=

        # Get QQIC value
        # @note May return a different value from value previously set, as a
        #   float encoding is used to encode big values. See {IGMPv3.decode}.
        # @return [Integer]
        def qqic
          IGMPv3.decode self[:qqic].to_i
        end

        # Set QQIC value
        # @note See {IGMPv3.encode}.
        # @param [Integer] value
        # @return [Integer]
        def qqic=(value)
          self[:qqic].value = IGMPv3.encode(value)
        end
      end
    end

    self.add_class IGMPv3::MQ
    IGMPv3.bind IGMPv3::MQ, type: 0x11
  end
end
