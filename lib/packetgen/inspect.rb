# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  # {Inspect} module provides methods to help writing +inspect+
  # @api private
  # @author Sylvain Daubert
  module Inspect
    # Maximum number of characters on a line for INSPECT
    MAX_WIDTH = 70
    # @private
    SEPARATOR = ('-' * MAX_WIDTH << "\n").freeze

    # Format to inspect attribute
    FMT_ATTR = "%14s %16s: %s\n"

    # Create a dashed line with +obj+ class writing in it
    # @param [String] name
    # @param [Integer] level
    # @return [String]
    def self.dashed_line(name, level=1)
      str = '--' * level << " #{name} "
      str << '-' * (MAX_WIDTH - str.length) << "\n"
    end

    # @return [String]
    def self.shift_level(level=1)
      '  ' * (level + 1)
    end

    # @param [#to_i] value
    # @param [Integer] hexsize
    # @return [String]
    def self.int_dec_hex(value, hexsize)
      fmt = "%-16s (0x%0#{hexsize}x)"
      fmt % [value.to_i, value.to_i]
    end

    # @param [String] str
    # @param [Integer] int
    # @param [Integer] hexsize
    # @return [String]
    def self.enum_human_hex(str, int, hexsize)
      fmt = "%-16s (0x%0#{hexsize}x)"
      fmt % [str, int]
    end

    # Simple formatter to inspect an attribute
    # @param [String] type attribute type
    # @param [String] attr attribute name
    # @param [String] value
    # @param [Integer] level
    # @return [String]
    def self.format(type, attr, value, level=1)
      str = Inspect.shift_level(level)
      str << Inspect::FMT_ATTR % [type, attr, value]
    end

    # Format an attribute for +#inspect+.
    # 3 cases are handled:
    # * attribute value is a {Types::Int}: show value as integer and in
    #   hexdecimal format,
    # * attribute value responds to +#to_human+: call it,
    # * else, +#to_s+ is used to format attribute value.
    # @param [Symbol] attr attribute name
    # @param [Object] value attribute value
    # @param [Integer] level
    # @return [String]
    def self.inspect_attribute(attr, value, level=1)
      type = value.class.to_s.sub(/.*::/, '')
      self.format(type, attr, value.format_inspect, level)
    end

    # Format a ASN.1 attribute for +#inspect+.
    # 4 cases are handled:
    # * attribute value is a =RANS1::Types::Enumerated+: show named value and
    #   its integer value as hexdecimal format,
    # * attribute value is a +RASN1::Types::Integer+: show value as integer and in
    #   hexdecimal format,
    # * attribute value is a +RASN1::Model+: only show its root type,
    # * else, +#to_s+ is used to format attribute value.
    # @param [Symbol] name attribute name
    # @param [RASN1::Types::Base,RASN1::Model] attr attribute
    # @param [Integer] level
    # @return [String]
    def self.inspect_asn1_attribute(name, attr, level=1)
      str = shift_level(level)
      val = case attr
            when RASN1::Types::Enumerated
              hexsize = attr.value_size * 2
              fmt = "%-16s (0x%0#{hexsize}x)"
              fmt % [attr.value, attr.to_i]
            when RASN1::Types::Integer
              int_dec_hex(attr.value, attr.value_size * 2)
            when RASN1::Model
              attr.root.type
            else
              attr.value.to_s.inspect
            end
      str << FMT_ATTR % [attr.type, name, val]
    end

    # @param [#to_s] body
    # @return [String]
    def self.inspect_body(body, name='Body')
      return '' if body.nil? || body.empty?

      str = dashed_line(name, 2)
      0.upto(15) { |v| str << ' %02d' % v }
      str << "\n" << SEPARATOR
      unless body.empty?
        (body.size / 16 + 1).times do |i|
          str << self.convert_body_slice(body.to_s[i * 16, 16])
        end
      end
      str << SEPARATOR
    end

    # @private
    def self.convert_body_slice(bslice)
      octets = bslice.unpack('C*')
      str = octets.map { |v| ' %02x' % v }.join
      str << ' ' * (48 - str.size) unless str.size >= 48
      str << '  ' << octets.map { |v| (32..127).cover?(v) ? v.chr : '.' }.join
      str << "\n"
    end
  end
end
