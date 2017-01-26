# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11

      # IEEE802.11 information element
      # @author Sylvain Daubert
      class Element < Types::TLV
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
    end
  end
end
