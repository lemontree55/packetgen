# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # IEEE 802.1Q VLAN tagging
    #
    # A VLAN tag consists of:
    # * a {#tci Tag Control Information} (+BinStruct::Int16+),
    # * a {#ethertype} (+BinStruct::Int16+),
    # * and a body (a +BinStruct::String+ or another {Headerable} class).
    #
    # @example Create a Dot1q header
    #   # Create a IP packet in VLAN #43
    #   pkt = PacketGen.gen('Eth').add('Dot1q', vid: 43).add('IP')
    #   pkt.is?('Dot1q')   #=> true
    # @author Sylvain Daubert
    # @since 1.4.0
    class Dot1q < Base
      # @!attribute tci
      #  @return [Integer] 16-bit Tag Control Information
      # @!attribute pcp
      #  @return [Integer] 3-bit Priority Code Point from {#tci}
      # @!attribute dei
      #  @return [Boolean] Drop Eligible Indicator from {#tci}
      # @!attribute vid
      #  @return [Integer] 12-bit VLAN ID from {#tci}
      define_bit_attr :tci, pcp: 3, dei: 1, vid: 12
      # @!attribute ethertype
      #  @return [Integer] 16-bit EtherType
      define_attr :ethertype, BinStruct::Int16
      # @!attribute body
      #  @return [BinStruct::String,Header::Base]
      define_attr :body, BinStruct::String
    end

    Eth.bind Dot1q, ethertype: 0x8100
  end
end
