module PacketGen

  # {Inspect} module provides methods to help writing +inspect+
  # @api private
  # @author Sylvain Daubert
  module Inspect

    # Maximum number of characters on a line for INSPECT
    INSPECT_MAX_WIDTH = 70

    # Create a dashed line with +obj+ class writing in it
    # @param [Object] obj
    # @param [Integer] level
    # @return [String]
    def self.dashed_line(name, level=1)
      str = '--' * level << " #{name} "
      str << '-' * (INSPECT_MAX_WIDTH - str.length) << "\n"
    end


    # @param [Symbol] attr attribute name
    # @param [Object] value attribute value
    # @param [Integer] level
    # @return [String]
    def self.inspect_attribute(attr, value, level=1)
      str = '  ' + '  ' * level
      val = if value.is_a? StructFu::Int
              sz = value.to_s.size
              "%-10s (0x%0#{2*sz}x)" % [value.to_i, value.to_i]
            elsif value.respond_to? :to_x
              value.to_x
            else
              value.to_s
            end
      str << "%7s %12s: %s" % [value.class.to_s.sub(/.*::/, ''), attr, val]
      str << "\n"
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