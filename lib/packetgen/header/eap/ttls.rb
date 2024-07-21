# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class EAP
      # Extensible Authentication Protocol (EAP) - Tunneled-TLS,
      # {https://tools.ietf.org/html/rfc5281 RFC 5281}
      #
      # {EAP::TTLS} has following fields:
      # * {#flags} ({BinStruct::Int8}),
      # * optionally {#message_length} ({BinStruct::Int32}), if +#l?+ is +true+,
      # * {#body} ({BinStruct::String}).
      # @author Sylvain Daubert
      # @since 2.1.4
      class TTLS < EAP
        update_attr :type, default: 21
        # @!attribute flags
        #  @return [Integer] 8-bit flags
        define_attr_before :body, :flags, BinStruct::Int8

        # @!attribute l
        #  Say if length field is included. Defined on {#flags} field.
        #  @return [Boolean]
        # @!attribute m
        #  Say if there are more fragments. Defined on {#flags} field.
        #  @return [Boolean]
        # @!attribute s
        #  If set, this message is a TLS-Start. Defined on {#flags} field.
        #  @return [Boolean]
        # @!attribute reserved
        #  @return [Integer] 2-bit reserved integer
        # @!attribute version
        #  @return [Integer] 3-bit version
        define_bit_attrs_on :flags, :l, :m, :s, :reserved, 2, :version, 3
        alias length_present? l?
        alias more_fragments? m?
        alias tls_start? s?

        # @!attribute message_length
        #  Message length. This field provides the total length of the
        #  raw data message sequence prior to fragmentation. So, it
        #  cannot be automatically calculated (no +#calc_length+ method).
        #  @return [Integer] 32-bit message length
        define_attr_before :body, :message_length, BinStruct::Int32,
                           optional: lambda(&:l?)

        # @return [String]
        def inspect
          super do |attr|
            next unless attr == :flags

            shift = Inspect.shift_level
            str = shift.dup
            value = %i[l m s].map { |f| send(:"#{f}?") ? f.to_s : '.' }.join
            value = '%-16s (0x%02x)' % [value, self.flags]
            str << Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''),
                                        attr, value]
            str << shift
            str << Inspect::FMT_ATTR % ['', 'version', self.version]
          end
        end
      end
    end
  end
end
