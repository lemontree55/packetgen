# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class SCTP
      # Mixin to handle 32-bit padding in SCTP classes
      module Padded32
        # Handle padding
        # @param [Bool] no_padding
        # @return [::String]
        def to_s(no_padding: false)
          s = super()
          return s if no_padding

          padlen = -(s.size % -4)
          s << "\x00".b * padlen
        end

        # Say if binary string is padded
        # @return [bool]
        def padded?
          str = to_s(no_padding: true)
          (str.size % 4).positive?
        end
      end
    end
  end
end
