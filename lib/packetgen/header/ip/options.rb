# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class IP
      # Class to handle IP options
      # @author Sylvain Daubert
      class Options < Types::Array
        set_of Option

        HUMAN_SEPARATOR = ';'

        # Get binary string
        # @return [String]
        def to_s
          str = super
          str += ([0] * (4 - (str.length % 4))).pack('C*') if str.length % 4 != 0
          str
        end

        private

        def record_from_hash(hsh)
          Option.build(hsh)
        end

        def real_type(opt)
          types = Option.types
          types.value?(opt.type) ? IP.const_get(types.key(opt.type)) : opt.class
        end
      end
    end
  end
end
