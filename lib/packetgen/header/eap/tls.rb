# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class EAP
      # Extensible Authentication Protocol (EAP) - TLS,
      # {https://tools.ietf.org/html/rfc5216 RFC 5216}
      #
      # {EAP::TLS} has following fields:
      # * {#flags} ({Types::Int8}),
      # * optionally {#tls_length} ({Types::Int32}), if +#l?+ is +true+,
      # * {#body} ({Types::String}).
      # @author Sylvain Daubert
      # @since 2.1.4
      class TLS < EAP
        update_field :type, default: 13
        # @!attribute flags
        #  @return [Integer] 8-bit flags
        define_field_before :body, :flags, Types::Int8

        # @!attribute l
        #  Say if length field is included. Defined on {#flags} field.
        #  @return [Boolean]
        # @!attribute m
        #  Say if there are more fragments. Defined on {#flags} field.
        #  @return [Boolean]
        # @!attribute s
        #  If set, this message is a TLS-Start. Defined on {#flags} field.
        #  @return [Boolean]
        define_bit_fields_on :flags, :l, :m, :s, :reserved, 5
        alias length_present? l?
        alias more_fragments? m?
        alias tls_start? s?

        # @!attribute tls_length
        #  TLS message length. This field provides the total length of the
        #  TLS message or set of messages that is being fragmented. So, it
        #  cannot be automatically calculated (no +#calc_length+ method).
        #  @return [Integer] 32-bit TLS length
        define_field_before :body, :tls_length, Types::Int32,
                            optional: ->(h) { h.l? }

        # @return [String]
        def inspect
          super do |attr|
            next unless attr == :flags

            str = Inspect.shift_level
            value = %i[l m s].map { |f| send("#{f}?") ? f.to_s : '.' }.join
            value = '%-16s (0x%02x)' % [value, self.flags]
            str << Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''),
                                        attr, value]
          end
        end
      end
    end
  end
end
