module PacketGen

  # {Inspect} module provides methods to help writing +inspect+
  # @api private
  # @author Sylvain Daubert
  module Inspect

    # Maximum number of characters on a line for INSPECT
    INSPECT_MAX_WIDTH = 70

    # Format to inspect attribute
    INSPECT_FMT_ATTR = "%7s %12s: %s\n"

    # Create a dashed line with +obj+ class writing in it
    # @param [String] name
    # @param [Integer] level
    # @return [String]
    def self.dashed_line(name, level=1)
      str = '--' * level << " #{name} "
      str << '-' * (INSPECT_MAX_WIDTH - str.length) << "\n"
    end

    # @return [String]
    def self.shift_level(level=1)
      '  ' + '  ' * level
    end

    # @param [#to_i] value
    # @param [Integer] hex_size
    # @return [String]
    def self.int_dec_hex(value, hexsize)
      "%-10s (0x%0#{hexsize}x)" % [value.to_i, value.to_i]
    end

    # Format an attribute for +#inspect+.
    # 3 cases are handled:
    # * attribute value is a {StructFu::Int}: show value as integer and in
    #   hexdecimal format,
    # * attribute value responds to +#to_human+: call it,
    # * else, +#to_s+ is used to format attribute value.
    # @param [Symbol] attr attribute name
    # @param [Object] value attribute value
    # @param [Integer] level
    # @return [String]
    def self.inspect_attribute(attr, value, level=1)
      str = shift_level(level)
      val = if value.is_a? StructFu::Int
              int_dec_hex(value, value.to_s.size * 2)
            elsif value.respond_to? :to_human
              value.to_human
            else
              value.to_s
            end
      str << INSPECT_FMT_ATTR % [value.class.to_s.sub(/.*::/, ''), attr, val]
    end

    # @param [#to_s] body
    # @return [String]
    def self.inspect_body(body)
      str = dashed_line('Body', 2)
      str << (0..15).to_a.map { |v| " %02d" % v}.join << "\n"
      str << '-' * INSPECT_MAX_WIDTH << "\n"
      if body.size > 0
        (body.size / 16 + 1).times do |i|
          octets = body.to_s[i*16, 16].unpack('C*')
          o_str = octets.map { |v| " %02x" % v}.join
          str << o_str
          str << ' ' * (3*16 - o_str.size) unless o_str.size >= 3*16
          str << '  ' << octets.map { |v| v < 128 && v > 13 ? v.chr : '.' }.join
          str << "\n"
        end
      end
      str << '-' * INSPECT_MAX_WIDTH << "\n"
    end
  end
end
