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
        update_attr :type, default: 4
        remove_attr :body

        # @!attribute value_size
        #  8-bit size of the {#value} attribute.
        #  @return [Integer]
        define_attr :value_size, BinStruct::Int8
        # @!attribute value
        #  MD5 challenge value, as an octet stream, as per {https://datatracker.ietf.org/doc/html/rfc1994#section-4 RFC1994}
        #  @return [::String]
        define_attr :value, BinStruct::String,
                    builder: ->(h, t) { t.new(length_from: h[:value_size]) }
        # @!attribute name
        #  Name identifying the system sending the packet. It is or or more octets. Its size is
        #  determined from the {#length} attribute.
        #  @return [::String]
        # @since 4.1.0 Attribute renamed from +optioanl_name+ to +name+
        define_attr :name, BinStruct::String

        # @deprecated
        alias optional_name name
      end
    end
  end
end
