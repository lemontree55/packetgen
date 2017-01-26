# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11

      class Beacon < Management
        define_field_before :body, :timestamp, Types::Int64le
        define_field_before :body, :interval, Types::Int16le, default: 0x64
        define_field_before :body, :capabilities, Types::Int16
      end
    end
  end
end
