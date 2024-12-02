# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class EAP
      # Extensible Authentication Protocol (EAP) - TLS,
      # {https://tools.ietf.org/html/rfc5216 RFC 5216}
      #
      # {EAP::TLS} has following fields:
      # * {#flags} ({BinStruct::Int8}),
      # * optionally {#tls_length} ({BinStruct::Int32}), if +#l?+ is +true+,
      # * {#body} ({BinStruct::String}).
      # @author Sylvain Daubert
      # @since 2.1.4
      class TLS < EAP
        update_attr :type, default: 13
        # @!attribute flags
        #  @return [Integer] 8-bit flags
        # @!attribute l
        #  Say if length field is included
        #  @return [Integer]
        # @!attribute m
        #  Say if there are more fragments
        #  @return [Integer]
        # @!attribute s
        #  If set, this message is a TLS-Start
        #  @return [Integer]
        define_bit_attr_before :body, :flags, l: 1, m: 1, s: 1, reserved: 5
        alias length_present? l?
        alias more_fragments? m?
        alias tls_start? s?

        # @!attribute tls_length
        #  TLS message length. This field provides the total length of the
        #  TLS message or set of messages that is being fragmented. So, it
        #  cannot be automatically calculated (no +#calc_length+ method).
        #  @return [Integer] 32-bit TLS length
        define_attr_before :body, :tls_length, BinStruct::Int32,
                           optional: lambda(&:l?)

        # @return [String]
        def inspect
          super do |attr|
            next unless attr == :flags

            str = Inspect.shift_level
            value = %i[l m s].map { |f| send(:"#{f}?") ? f.to_s : '.' }.join
            value = '%-16s (0x%02x)' % [value, self.flags]
            str << Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''),
                                        attr, value]
          end
        end
      end
    end
  end
end
