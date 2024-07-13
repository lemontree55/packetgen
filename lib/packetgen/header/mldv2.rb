# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # This module contains all MLDv2 specific classes.
    # @author Sylvain Daubert
    # @since 2.4.0
    module MLDv2
      # Encode value for MLDv2 Max Resp Code.
      # Value may be encoded as a float, so some error may occur.
      # See RFC 3810 §5.1.3
      # @param [Integer] value value to encode
      # @return [Integer]
      def self.encode(value)
        if value < 32_768
          value
        elsif value > 8_387_583
          0xffff
        else
          exp = 0
          value >>= 3
          while value > 8_191
            exp += 1
            value >>= 1
          end
          0x8000 | ((exp & 7) << 12) | (value & 0xfff)
        end
      end

      # Decode value for MLDv2 Max Resp Code.
      # See RFC 3810 §5.1.3
      # @param [Integer] value value to decode
      # @return [Integer]
      def self.decode(value)
        if value < 32_768
          value
        else
          mant = value & 0xfff
          exp = (value >> 12) & 0x7
          (0x1000 | mant) << (exp + 3)
        end
      end
    end
  end
end

require_relative 'mldv2/mlq'
require_relative 'mldv2/mlr'
