# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11
      # IEEE 802.11 control frame header
      #
      # This class make a {Dot11} header with {#type} set to +1+
      # (control frame).
      #
      # A IEEE 802.11 control header consists of:
      # * a {#frame_ctrl} ({BinStruct::Int16}),
      # * a {#id}/duration ({BinStruct::Int16le}),
      # * a {#mac1} ({Eth::MacAddr}).
      # * sometimes a {#mac2} ({Eth::MacAddr}),
      # * a {#body} (a {BinStruct::String} or another {Base} class),
      # * and a Frame check sequence ({#fcs}, of type {BinStruct::Int32le}).
      # @author Sylvain Daubert
      class Control < Dot11
        # Control subtypes
        SUBTYPES = {
          7 => 'Wrapper',
          8 => 'Block Ack Request',
          9 => 'Block Ack',
          10 => 'PS-Poll',
          11 => 'RTS',
          12 => 'CTS',
          13 => 'Ack',
          14 => 'CF-End',
          15 => 'CF-End+CF-Ack'
        }.freeze

        # Control subtypes with mac2 field
        SUBTYPES_WITH_MAC2 = [9, 10, 11, 14, 15].freeze

        # @param [Hash] options
        # @see Base#initialize
        def initialize(options={})
          super({ type: 1 }.merge!(options))
          @applicable_attributes -= %i[mac3 sequence_ctrl mac4 qos_ctrl ht_ctrl]
          define_applicable_attributes
        end

        # Get human readable subtype
        # @return [String]
        def human_subtype
          SUBTYPES[subtype] || subtype.to_s
        end

        private

        def define_applicable_attributes
          super
          if @applicable_attributes.include? :mac2
            @applicable_attributes -= %i[mac2] unless SUBTYPES_WITH_MAC2.include? self.subtype
          elsif SUBTYPES_WITH_MAC2.include? self.subtype
            @applicable_attributes[3, 0] = :mac2
          end
        end
      end
    end
  end
end
