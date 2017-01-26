# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11

      class Management < Dot11
        def initialize(options={})
          super({type: 0}.merge!(options))
          @applicable_fields -= %i(mac4 qos_control ht_control)
        end

        def read(str)
          private_read str
        end

        def order=(bool)
          if bool && !@applicable_fields.include?(:ht_control)
            @applicable_fields[5, 0] = :ht_control
          elsif !bool && @applicable_fields.include?(:ht_control)
            @applicable_fields -= %i(ht_control)
          end
          super
        end
      end
    end
  end
end
