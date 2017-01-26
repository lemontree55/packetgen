# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11

      SUBTYPES = {
        7  => 'Wrapper',
        8  => 'Block Ack Request',
        9  => 'Block Ack',
        10 => 'PS-Poll',
        11 => 'RTS',
        12 => 'CTS',
        13 => 'Ack',
        14 => 'CF-End',
        15 => 'CF-End+CF-Ack'
      }.freeze

      SUBTYPES_WITH_MAC2 = [9, 10, 11, 14, 15].freeze

      class Control < Dot11
        def initialize(options={})
          super({type: 1}.merge!(options))
          @applicable_fields -= %i(mac3 sequence_control mac4 qos_control ht_control)
          @applicable_fields -= %i(mac2) unless SUBTYPES_WITH_MAC2.include? self.subtype
        end

        def read(str)
          private_read str
          if @applicable_fields.include? :mac2
            @applicable_fields -= %i(mac2) unless SUBTYPES_WITH_MAC2.include? self.subtype
          elsif SUBTYPES_WITH_MAC2.include? self.subtype
            sz = self.sz
            @applicable_fields += %i(mac2)
            self[:mac2].read str[sz, str.size]
          end
          self
        end

        def human_subtype
          SUBTYPES[subtype] || subtype.to_s
        end
      end
    end
  end
end
