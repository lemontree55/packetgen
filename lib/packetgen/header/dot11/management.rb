# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11
      # IEEE 802.11 management frame header
      #
      # This class make a {Dot11} header with {#type} set to +0+
      # (management frame).
      #
      # A IEEE 802.11 management header consists of:
      # * a {#frame_ctrl} ({Types::Int16}),
      # * a {#id}/duration ({Types::Int16le}),
      # * a {#mac1} ({Eth::MacAddr}).
      # * a {#mac2} ({Eth::MacAddr}),
      # * a {#mac3} ({Eth::MacAddr}),
      # * a {#sequence_ctrl} ({Types::Int16}),
      # * a {#body} (a {Types::String} or another {Base} class),
      # * and a Frame check sequence ({#fcs}, of type {Types::Int32le}).
      #
      # Management frames should be constructed with more headers from
      # {SubMngt} subclasses.
      #
      # By example, build a {DeAuth} frame:
      #   PacketGen.gen('Dot11::Management').add('Dot11::DeAuth')
      #
      # Some frames need to have {Element}. By example a {Beacon} frame:
      #   pkt = PacketGen.gen('Dot11::Management', mac1: broadcast, mac2: bssid, mac3: bssid).
      #                   add('Dot11::Beacon')
      #   pkt.dot11_beacon.add_elements(type: 'SSID', value: ssid)
      #   pkt.dot11_beacon.add_elements(type: 'Rates', value: "\x82\x84\x8b\x96\x12\x24\x48\x6c")
      #   pkt.dot11_beacon.add_elements(type: 'DSset', value: "\x06")
      #   pkt.dot11_beacon.add_elements(type: 'TIM', value: "\x00\x01\x00\x00")
      # @author Sylvain Daubert
      class Management < Dot11
        # @param [Hash] options
        # @see Base#initialize
        def initialize(options={})
          super({ type: 0 }.merge!(options))
          @applicable_fields -= %i[mac4 qos_ctrl ht_ctrl]
          define_applicable_fields
        end

        # Add an {Element}
        # @param [Integer,String] type element type
        # @param [Object] value element value
        # @return [self]
        # @since 2.1.3
        def add_element(type:, value:)
          raise FormatError, 'Before adding an Element, you have to add a Dot11::SubMngt subclass instance' unless self[:body].is_a? SubMngt

          self[:body].elements << { type: type, value: value }
          self
        end

        # Invert mac1 and mac2 (resp. destination address and source address).
        # @return [self]
        def reply!
          self[:mac1], self[:mac2] = self[:mac2], self[:mac1]
        end
      end
    end
  end
end
