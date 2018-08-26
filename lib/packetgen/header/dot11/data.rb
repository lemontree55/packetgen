# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class Dot11
      # IEEE 802.11 data frame header
      #
      # This class make a {Dot11} header with {#type} set to +2+
      # (data frame).
      #
      # A IEEE 802.11 data header consists of:
      # * a {#frame_ctrl} ({Types::Int16}),
      # * a {#id}/duration ({Types::Int16le}),
      # * a {#mac2} ({Eth::MacAddr}),
      # * a {#mac3} ({Eth::MacAddr}),
      # * a {#sequence_ctrl} ({Types::Int16}),
      # * sometimes a {#mac4} ({Eth::MacAddr}),
      # * sometimes a {#qos_ctrl} ({Types::Int16}),
      # * a {#body} (a {Types::String} or another {Base} class),
      # * and a Frame check sequence ({#fcs}, of type {Types::Int32le}).
      # @author Sylvain Daubert
      class Data < Dot11
        # @param [Hash] options
        # @see Base#initialize
        def initialize(options={})
          super({ type: 2 }.merge!(options))
          @applicable_fields -= %i[mac4 qos_ctrl ht_ctrl]
          define_applicable_fields
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
            self[:mac1], self[:mac2] = self[:mac2], self[:mac1]
          when 1
            # MAC1: RA/BSSID, MAC2: TA/SA, MAC3: DA
            self[:mac2], self[:mac1] = self[:mac1], self[:mac2]
            self.to_ds = false
            self.from_ds = true
          when 2
            # MAC1: RA/DA, MAC2: BSSID, MAC3: SA or BSSID
            self[:mac1], self[:mac2] = self[:mac2], self[:mac1]
            self.to_ds = true
            self.from_ds = false
          when 3
            # MAC1: RA, MAC2: TA
            self[:mac1], self[:mac2] = self[:mac2], self[:mac1]
            # MAC3: DA, MAC4: SA
            self[:mac4], self[:mac3] = self[:mac3], self[:mac4]
          end
          self
        end

        private

        def define_applicable_fields
          super
          if (subtype >= 8) && !@applicable_fields.include?(:qos_ctrl)
            # Insert after mac4, if present
            # else insert after sequence_ctrl
            if @applicable_fields.include? :mac4
              idx = @applicable_fields.index(:mac4)
              @applicable_fields[idx, 0] = :qos_ctrl
            else
              @applicable_fields[6, 0] = :qos_ctrl
            end
          elsif subtype < 8
            @applicable_fields -= %i[qos_ctrl]
          end
        end
      end
    end
  end
end
