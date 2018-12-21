# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class Dot11
      # IEEE 802.11 information element
      #
      # An {Element} is a piece of data contained in a Dot11 management frame.
      Element = Types::AbstractTLV.create

      class Element
        # Known element types
        TYPES = {
          0 =>   'SSID',
          1 =>   'Rates',
          2 =>   'FHset',
          3 =>   'DSset',
          4 =>   'CFset',
          5 =>   'TIM',
          6 =>   'IBSSset',
          16 =>  'challenge',
          42 =>  'ERPinfo',
          46 =>  'QoS Cap.',
          47 =>  'ERPinfo',
          48 =>  'RSNinfo',
          50 =>  'ESRates',
          68 =>  'reserved',
          221 => 'vendor'
        }.freeze
      end
      Element.define_type_enum Element::TYPES.invert

      # Array of {Element}.
      # @since 3.1.1
      class ArrayOfElements < Types::Array
        set_of Element
      end
    end
  end
end
