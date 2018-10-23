# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class IPv6
      # Option for {HopByHop} IPv6 extension header
      # @author Sylvain Daubert
      class Option < Types::TLV
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

        # Populate object from a binary string
        # @param [String] str
        # @return [self]
        def read(str)
          clear
          return self if str.nil?

          force_binary str
          until str.empty?
            obj = self.class.set_of_klass.new.read(str)
            obj = Pad1.new.read(str) if obj.type.zero?
            self.push obj
            str.slice!(0, obj.sz)
          end
          self
        end

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
        define_field_before :body, :options, Options

        # Populate object from a binary string
        # @param [String] str
        # @return [self]
        def read(str)
          return self if str.nil?

          force_binary str
          self[:next].read str[0, 1]
          self[:length].read str[1, 1]
          self[:options].read str[2, real_length - 2]
          self[:body].read str[real_length..-1]
          self
        end
      end
    end

    self.add_class IPv6::HopByHop
    IPv6.bind IPv6::HopByHop, next: 0
  end
end
