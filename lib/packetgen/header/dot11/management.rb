# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11

      # IEEE 802.11 management frame header
      # @author Sylvain Daubert
      class Management < Dot11

        # @param [Hash] options
        # @see Base#initialize
        def initialize(options={})
          super({type: 0}.merge!(options))
          @applicable_fields -= %i(mac4 qos_ctrl ht_ctrl)
          define_applicable_fields
        end
      end
    end
  end
end
