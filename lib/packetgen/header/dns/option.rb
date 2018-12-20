# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DNS
      # DNS option
      Option = Types::AbstractTLV.create(type_class: Types::Int16,
                                         length_class: Types::Int16)

      class ArrayOfOptions < Types::Array
        set_of Option
      end
    end
  end
end
