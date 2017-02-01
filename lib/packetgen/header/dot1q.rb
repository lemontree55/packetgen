# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # IEEE 802.1Q VLAN tagging
    #
    # A VLAN tag consists of:
    # * a {#tci Tag Control Information} ({Types::Int16}),
    # * a {#ethertype} ({Types::Int16}),
    # * and a body (a {Types::String} or another Header class).
    # @author Sylvain Daubert
    class Dot1q < Base
      # @!attribute tci
      #  @return [Integer] 16-bit Tag Control Information
      define_field :tci, Types::Int16
      # @!attribute ethertype
      #  @return [Integer] 16-bit EtherType
      define_field :ethertype, Types::Int16
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

      # @!attribute pcp
      #  @return [Integer] 3-bit Priority Code Point from {#tci}
      # @!attribute dei
      #  @return [Boolean] Drop Eligible Indicator from {#tci}
      # @!attribute vid
      #  @return [Integer] 12-bit VLAN ID from {#tci}
      define_bit_fields_on :tci, :pcp, 3, :dei, :vid, 12
    end

    Eth.bind_header Dot1q, ethertype: 0x8100
  end
end
