# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # IEEE 802.1X / EAPOL
    #
    # A IEEE 802.1X header consists of:
    # * a {#version} ({BinStruct::Int8}),
    # * a packet {#type} ({BinStruct::Int8}),
    # * a {#length} ({BinStruct::Int16}),
    # * and a body (a {BinStruct::String} or another Header class).
    # == Create a Dot1x header
    #   pkt1 = PacketGen.gen('Eth').add('Dot1x', type: 1)
    #   pkt2 = PacketGen.gen('Eth').add('Dot1x')
    #   pkt2.dot1x.type = 'EAP Packet'
    #   pkt2.dot1x.body.read 'body'
    # @author Sylvain Daubert
    # @since 1.4.0
    class Dot1x < Base
      # IEEE 802.1x Ether type
      ETHERTYPE = 0x888e

      # IEEE 802.1X packet types
      TYPES = {
        'EAP Packet' => 0,
        'Start' => 1,
        'Logoff' => 2,
        'Key' => 3,
        'Encap-ASF-Alert' => 4
      }.freeze

      # @!attribute version
      #  @return [Integer] 8-bit Protocol Version
      define_attr :version, BinStruct::Int8, default: 1
      # @!attribute type
      #  @return [Integer] 8-bit Packet Type
      define_attr :type, BinStruct::Int8Enum, enum: TYPES
      # @!attribute length
      #  @return [Integer] 16-bit body length
      define_attr :length, BinStruct::Int16
      # @!attribute body
      #  @return [BinStruct::String,Header::Base]
      define_attr :body, BinStruct::String, builder: ->(h, t) { t.new(length_from: h[:length]) }

      # Get human readable type
      # @return [String]
      def human_type
        self[:type].to_human
      end

      # Calculate and set body length
      # @return [Integer]
      # @since 2.1.4
      def calc_length
        Base.calculate_and_set_length self, header_in_size: false
      end
    end

    Eth.bind Dot1x, ethertype: Dot1x::ETHERTYPE
    SNAP.bind Dot1x, proto_id: Dot1x::ETHERTYPE
  end
end
