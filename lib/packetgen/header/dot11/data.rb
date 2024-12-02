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
      # IEEE 802.11 data frame header
      #
      # This class make a {Dot11} header with {#type} set to +2+
      # (data frame).
      #
      # A IEEE 802.11 data header consists of:
      # * a {#frame_ctrl} ({BinStruct::Int16}),
      # * a {#id}/duration ({BinStruct::Int16le}),
      # * a {#mac2} ({Eth::MacAddr}),
      # * a {#mac3} ({Eth::MacAddr}),
      # * a {#sequence_ctrl} ({BinStruct::Int16}),
      # * sometimes a {#mac4} ({Eth::MacAddr}),
      # * sometimes a {#qos_ctrl} ({BinStruct::Int16}),
      # * a {#body} (a {BinStruct::String} or another {Base} class),
      # * and a Frame check sequence ({#fcs}, of type {BinStruct::Int32le}).
      # @author Sylvain Daubert
      class Data < Dot11
        # @param [Hash] options
        # @see Base#initialize
        def initialize(options={})
          super({ type: 2 }.merge!(options))
          @applicable_attributes -= %i[mac4 qos_ctrl ht_ctrl]
          define_applicable_attributes
        end

        # Invert source and destination addresses (see Table 8-19 from
        # IEEE 802.11-2012 document to known which MAC is SA, and which
        # one is DA).
        # Also invert Receiver and Transmitter address in case ToDS and
        # FromDS are true.
        def reply!
          ds = frame_ctrl & 3
          case ds
          when 0
            # MAC1: RA/DA, MAC2: TA/SA
            invert_mac(:mac1, :mac2)
          when 1
            # MAC1: RA/BSSID, MAC2: TA/SA, MAC3: DA
            invert_mac(:mac1, :mac2)
            self.to_ds = false
            self.from_ds = true
          when 2
            # MAC1: RA/DA, MAC2: BSSID, MAC3: SA or BSSID
            invert_mac(:mac1, :mac2)
            self.to_ds = true
            self.from_ds = false
          when 3
            # MAC1: RA, MAC2: TA
            invert_mac(:mac1, :mac2)
            # MAC3: DA, MAC4: SA
            invert_mac(:mac3, :mac4)
          end
          self
        end

        # Get destination MAC address
        # @return [String]
        def dst
          _src_mac, dst_mac = src_dst_from_mac
          self.send(dst_mac)
        end

        # Set destination MAC address
        # @param [String] mac MAC address to set
        # @return [String]
        def dst=(mac)
          _src_mac, dst_mac = src_dst_from_mac
          self.send(:"#{dst_mac}=", mac)
        end

        # Get source MAC address
        # @return [String]
        def src
          src_mac, = src_dst_from_mac
          self.send(src_mac)
        end

        # Set source MAC address
        # @param [String] mac MAC address to set
        # @return [String]
        def src=(mac)
          src_mac, = src_dst_from_mac
          self.send(:"#{src_mac}=", mac)
        end

        private

        def src_dst_from_mac
          ds = frame_ctrl & 3
          case ds
          when 0
            %i[mac2 mac1]
          when 1
            %i[mac2 mac3]
          when 2
            %i[mac3 mac1]
          when 3
            %i[mac4 mac3]
          end
        end

        def define_applicable_attributes
          super
          if (subtype >= 8) && !@applicable_attributes.include?(:qos_ctrl)
            # Insert after mac4, if present
            # else insert after sequence_ctrl
            if @applicable_attributes.include? :mac4
              idx = @applicable_attributes.index(:mac4)
              @applicable_attributes[idx, 0] = :qos_ctrl
            else
              @applicable_attributes[6, 0] = :qos_ctrl
            end
          elsif subtype < 8
            @applicable_attributes -= %i[qos_ctrl]
          end
        end

        def invert_mac(mac1, mac2)
          self[mac1], self[mac2] = self[mac2], self[mac1]
        end
      end
    end
  end
end
