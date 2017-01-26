# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11

      attr_accessor :elements

      class Management < Dot11
        def initialize(options={})
          super
          @applicable_fields -= %i(mac4 qos_control ht_control)
          @elements = []
        end

        def read(str)
          private_read str
          read_elements self[:body]
          self[:body].read ''
          self
        end

        def order=(bool)
          if bool && !@applicable_fields.include?(:ht_control)
            @applicable_fields[5, 0] = :ht_control
          elsif !bool && @applicable_fields.include?(:ht_control)
            @applicable_fields -= %i(ht_control)
          end
          super
        end

        def to_s
          super + @elements.map(&:to_s).join
        end

        def inspect
          str = super
          str << Inspect.dashed_line('Dot11 Elements', level=3)
          @elements.each do |el|
            str << Inspect.shift_level(4) << el.to_human << "\n"
          end
          str
        end

        private

        def read_elements(str)
          puts "read elements"
          start = 0
          elsz = Element.new.sz
          while str.size - start >= elsz  do
            el = Element.new.read(str[start, str.size])
            @elements << el
            start += el.sz
          end
        end
      end
    end
  end
end
