# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    # IEEE 802.1X / EAPOL
    #
    # A IEEE 802.1X header consists of:
    # * a {#version} ({Types::Int8}),
    # * a packet {#type} ({Types::Int8}),
    # * a {#length} ({Types::Int16}),
    # * and a body (a {Types::String} or another Header class).
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
      define_field :version, Types::Int8, default: 1
      # @!attribute type
      #  @return [Integer] 8-bit Packet Type
      define_field :type, Types::Int8Enum, enum: TYPES
      # @!attribute length
      #  @return [Integer] 16-bit body length
      define_field :length, Types::Int16
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String, builder: ->(h, t) { t.new(length_from: h[:length]) }

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
