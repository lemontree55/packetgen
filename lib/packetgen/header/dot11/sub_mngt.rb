# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11

      # @abstract base class for all subtype management frames
      # @author Sylvain Daubert
      class SubMngt < Base
        attr_accessor :elements

        def initialize(options={})
          super
          @elements = []
        end

        def read(str)
          super
          read_elements str[sz, str.size] || ''
          self
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
          start = 0
          elsz = Element.new.sz
          while str.size - start >= elsz  do
            el = Element.new.read(str[start, str.size])
            @elements << el
            start += el.sz
          end
        end
      end

      # Dot11 Beacon frame
      class AssoReq < SubMngt
        define_field :cap, Types::Int16le
        define_field :listen_interval, Types::Int16le, default: 0x00c8
      end
      Header.add_class AssoReq
      Management.bind_header AssoReq, op: :and, type: 0, subtype: 0

      # Dot11 Beacon frame
      class AssoResp < SubMngt
        define_field :cap, Types::Int16le
        define_field :status, Types::Int16le
        define_field :aid, Types::Int16le
      end
      Header.add_class AssoResp
      Management.bind_header AssoResp, op: :and, type: 0, subtype: 1

      # Dot11 Beacon frame
      class ReAssoReq < AssoReq
        define_field :current_ap, Eth::MacAddr
      end
      Header.add_class ReAssoReq
      Management.bind_header ReAssoReq, op: :and, type: 0, subtype: 2

      # Dot11 Beacon frame
      class ReAssoResp < AssoResp
      end
      Header.add_class ReAssoResp
      Management.bind_header ReAssoResp, op: :and, type: 0, subtype: 3

      # Dot11 Beacon frame
      class ProbeReq < SubMngt
      end
      Header.add_class ProbeReq
      Management.bind_header ProbeReq, op: :and, type: 0, subtype: 4

      # Dot11 Beacon frame
      class ProbeResp < SubMngt
        define_field :timestamp, Types::Int64le
        define_field :beacon_interval, Types::Int16le, default: 0x0064
        define_field :cap, Types::Int16le
      end
      Header.add_class ProbeResp
      Management.bind_header ProbeResp, op: :and, type: 0, subtype: 5

      # Dot11 Beacon frame
      class Beacon < SubMngt
        define_field :timestamp, Types::Int64le
        define_field :interval, Types::Int16le, default: 0x64
        define_field :cap, Types::Int16le
      end
      Header.add_class Beacon
      Management.bind_header Beacon, op: :and, type: 0, subtype: 8

      # Dot11 ATIM frame
      class ATIM < SubMngt; end
      Header.add_class ATIM
      Management.bind_header ATIM, op: :and, type: 0, subtype: 9

      # Dot11 Disassociation frame
      class Disas < SubMngt
        define_field :reason, Types::Int16le
      end
      Header.add_class Disas
      Management.bind_header Disas, op: :and, type: 0, subtype: 10

      # Dot11 Authentication frame
      class Auth < SubMngt
        define_field :algo, Types::Int16le
        define_field :seqnum, Types::Int16le
        define_field :status, Types::Int16le
      end
      Header.add_class Auth
      Management.bind_header Auth, op: :and, type: 0, subtype: 11

      # Dot11 Deauthentication frame
      class DeAuth < SubMngt
        define_field :reason, Types::Int16le
      end
      Header.add_class DeAuth
      Management.bind_header DeAuth, op: :and, type: 0, subtype: 12
    end
  end
end
