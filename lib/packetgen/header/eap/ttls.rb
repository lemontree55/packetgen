# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class EAP
      # Extensible Authentication Protocol (EAP) - Tunneled-TLS,
      # {https://tools.ietf.org/html/rfc5281 RFC 5281}
      #
      # {EAP::TTLS} has following fields:
      # * {#flags} ({Types::Int8}),
      # * optionally {#message_length} ({Types::Int32}), if +#l?+ is +true+,
      # * {#body} ({Types::String}).
      # @author Sylvain Daubert
      # @since 2.1.4
      class TTLS < EAP
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
        # @!attribute reserved
        #  @return [Integer] 2-bit reserved integer
        # @!attribute version
        #  @return [Integer] 3-bit version
        define_bit_fields_on :flags, :l, :m, :s, :reserved, 2, :version, 3
        alias length_present? l?
        alias more_fragments? m?
        alias tls_start? s?

        # @!attribute message_length
        #  Message length. This field provides the total length of the
        #  raw data message sequence prior to fragmentation. So, it
        #  cannot be automatically calculated (no +#calc_length+ method).
        #  @return [Integer] 32-bit message length
        define_field_before :body, :message_length, Types::Int32,
                            optional: ->(h) { h.l? }

        # @return [EAP::TTLS]
        def initialize(options={})
          super({ type: 21 }.merge!(options))
        end

        # @return [String]
        def inspect
          str = Inspect.dashed_line(self.class, 2)
          fields.each do |attr|
            next if attr == :body
            next unless is_present?(attr)
            if attr == :flags
              shift = Inspect.shift_level(2)
              value = %i[l m s].map { |f| send("#{f}?") ? f.to_s : '.' }.join
              value = '%-10s (0x%02x)' % [value, self.flags]
              str << shift
              str << Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''),
                                          attr, value]
              str << Inspect::FMT_ATTR % ['', 'version', self.version]
            else
              str << Inspect.inspect_attribute(attr, self[attr], 2)
            end
          end
          str
        end
      end
    end
  end
end
