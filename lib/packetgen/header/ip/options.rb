# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

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
          if str.length % 4 != 0
            str += ([0] * (4 - (str.length % 4))).pack('C*')
          end
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
