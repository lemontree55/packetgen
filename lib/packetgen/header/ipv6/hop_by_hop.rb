# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class IPv6
      # @!parse
      #  # Option for {HopByHop} IPv6 extension header.
      #  # @since 3.1.0 subclass of {Types::AbstractTLV}
      #  class Option <AbstractTLV; end
      # @private
      Option = Types::AbstractTLV.create

      class Option
        # Known option types
        TYPES = {
          1 => 'padn',
          5 => 'router_alert'
        }.freeze

        # @return [String]
        def to_human
          case type
          when 1
            "pad#{self.sz}"
          else
            "#{human_type}(#{value.to_s.inspect})"
          end
        end
      end
      Option.define_type_enum Option::TYPES.invert

      # Special option pad1, for {HopByHop} IPv6 extension header
      # @author Sylvain Daubert
      class Pad1 < Types::Fields
        # @!attribute pad
        # @return [Integer]
        define_field :pad, Types::Int8, default: 0

        # @return [String]
        def to_human
          'pad1'
        end
      end

      # Array of {Option}, for {HopByHop} IPv6 extension header
      # @author Sylvain Daubert
      class Options < Types::Array
        set_of Option

        # Get options as a binary string. Add padding if needed.
        # @return [String]
        def to_s
          str = super
          case (str.size + 2) % 8
          when 0
            return str
          when 7
            # only on byte needed: use pad1 option
            self << Pad1.new
            str << [0].pack('C')
          else
            # use padn option
            len = 8 - 2 - (str.size % 8) - 2
            padn = Option.new(type: 'padn', value: "\x00" * len)
            self << padn
            str << padn.to_s
          end
          str
        end

        private

        def real_type(opt)
          opt.type.zero? ? Pad1 : opt.class
        end
      end

      # Hop-by-hop IPv6 extension
      #
      #   0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |  Next Header  |  Hdr Ext Len  |                               |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
      #  |                                                               |
      #  .                                                               .
      #  .                            Options                            .
      #  .                                                               .
      #  |                                                               |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #
      # Hop-by-hop IPv6 extension header consists of:
      # * a {#next} header field ({Types::Int8}),
      # * a {#length} field ({Types::Int8}),
      # * an {#options} field ({Options}),
      # * and a {#body}, containing next header.
      # @author Sylvain Daubert
      class HopByHop < Extension
        # redefine options field
        remove_field :options
        # @!attribute options
        #  Specific options of extension header
        #  @return [Options]
        define_field_before :body, :options, Options, builder: ->(h, t) { t.new(length_from: -> { h.real_length - 2 }) }
      end
    end

    self.add_class IPv6::HopByHop
    IPv6.bind IPv6::HopByHop, next: 0
  end
end
