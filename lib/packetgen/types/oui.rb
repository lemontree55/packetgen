# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types
    # OUI type, defined as a set of 3 bytes
    #  oui = OUI.new
    #  oui.from_human('00:01:02')
    #  oui.to_human   # => "00:01:02"
    # @author Sylvain Daubert
    class OUI < Types::Fields
      include Fieldable

      # @attribute b2
      #  @return [Integer] left-most byte
      define_field :b2, Types::Int8
      # @attribute b1
      #  @return [Integer] center byte
      define_field :b1, Types::Int8
      # @attribute b0
      #  @return [Integer] right-most byte
      define_field :b0, Types::Int8

      # Read a human-readable string to populate object
      # @param [String] str
      # @return [OUI] self
      def from_human(str)
        return self if str.nil?

        bytes = str.split(':')
        raise ArgumentError, 'not a OUI' unless bytes.size == 3

        self[:b2].read(bytes[0].to_i(16))
        self[:b1].read(bytes[1].to_i(16))
        self[:b0].read(bytes[2].to_i(16))
        self
      end

      # Get OUI in human readable form (colon-separated bytes)
      # @return [String]
      def to_human
        fields.map { |m| '%02x' % self[m] }.join(':')
      end
    end
  end
end
