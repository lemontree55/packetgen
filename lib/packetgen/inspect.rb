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

    # Format to inspect attribute
    FMT_ATTR = "%12s %12s: %s\n"

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
      '  ' + '  ' * level
    end

    # @param [#to_i] value
    # @param [Integer] hexsize
    # @return [String]
    def self.int_dec_hex(value, hexsize)
      "%-10s (0x%0#{hexsize}x)" % [value.to_i, value.to_i]
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
      str = shift_level(level)
      val = if value.is_a?(Types::Int) or value.is_a?(Integer)
              int_dec_hex(value, value.to_s.size * 2)
            elsif value.respond_to? :to_human
              value.to_human
            else
              value.to_s.inspect
            end
      str << FMT_ATTR % [value.class.to_s.sub(/.*::/, ''), attr, val]
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
              "%-10s (0x%0#{hexsize}x)" % [attr.value, attr.to_i]
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
      return '' if body.nil? or body.empty?
      str = dashed_line(name, 2)
      str << (0..15).to_a.map { |v| " %02d" % v}.join << "\n"
      str << '-' * MAX_WIDTH << "\n"
      if body.size > 0
        (body.size / 16 + 1).times do |i|
          octets = body.to_s[i*16, 16].unpack('C*')
          o_str = octets.map { |v| " %02x" % v}.join
          str << o_str
          str << ' ' * (3*16 - o_str.size) unless o_str.size >= 3*16
          str << '  ' << octets.map { |v| v < 128 && v > 31 ? v.chr : '.' }.join
          str << "\n"
        end
      end
      str << '-' * MAX_WIDTH << "\n"
    end
  end
end
