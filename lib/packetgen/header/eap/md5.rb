# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class EAP
      # Extensible Authentication Protocol (EAP) -
      # {https://tools.ietf.org/html/rfc3748#section-5.4 MD5 challenge}
      # @author Sylvain Daubert
      # @since 2.1.4
      class MD5 < EAP
        update_field :type, default: 4
        remove_field :body

        # @!attribute value_size
        #  @return [Integer] 8-bit value size
        define_field :value_size, Types::Int8
        # @!attribute value
        #  @return [::String]
        define_field :value, Types::String,
                     builder: ->(h, t) { t.new(length_from: h[:value_size]) }
        # @!attribute optional_name
        #  @return [::String]
        define_field :optional_name, Types::String
      end
    end
  end
end
