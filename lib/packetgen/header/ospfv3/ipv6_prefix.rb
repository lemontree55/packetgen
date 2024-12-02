# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3
      # This class handles IPv6 prefixes, as defined in RFC 5340 §A.4.1.
      # A IPv6 prefix consists of:
      # * a 8-bit {#length} field (length of the prefix, in bits),
      # * a 8-bit {#options} field, giving prefix capabilities,
      # * a 16-bit {#reserved} field (but it may be used in some LSA),
      # * and an array of 32-bit words to encode prefix itself ({#prefix}). This
      #   array consumes ((PrefixLength + 31) / 32) 32-bit words.
      # @author Sylvain Daubert
      class IPv6Prefix < BinStruct::Struct
        include BinStruct::Structable

        # @!attribute length
        #  Prefix length, in bits
        #  @return [Integer]
        define_attr :length, BinStruct::Int8
        # @!attribute options
        #  Prefix capabilities. See also capability bits: {#dn_opt}, {#p_opt},
        #  {#la_opt} and {#nu_opt}.
        #  @return [Options]
        # @!attribute dn_opt
        #  This bit controls an inter-area-prefix-LSAs or AS-external-LSAs
        #  re-advertisement in a VPN environment.
        #  @return [Integer]
        # @!attribute p_opt
        #  The "propagate" bit.  Set on NSSA area prefixes that should be
        #  readvertised by the translating NSSA area border.
        #  @return [Integer]
        # @!attribute la_opt
        #  The "local address" capability bit.  If set, the prefix is
        #  actually an IPv6 interface address of the Advertising Router.
        #  @return [Integer]
        # @!attribute nu_opt
        #  The "no unicast" capability bit.  If set, the prefix should be
        #  excluded from IPv6 unicast calculations.
        #  @return [Integer]
        define_bit_attr :options, zz: 3, dn_opt: 1, p_opt: 1, z: 1, la_opt: 1, nu_opt: 1
        # @!attribute reserved
        #  Reserved field in most of LSA types.
        #  @return [Integer]
        define_attr :reserved, BinStruct::Int16
        # @!attribute prefix
        #  IPv6 Prefix as an array of 32-bit words
        #  @return [Prefix]
        define_attr :prefix, BinStruct::ArrayOfInt32, builder: ->(h, t) { t.new(length_from: -> { h.length / 8 }) }

        # Get human-readable prefix
        # @return [String]
        def to_human
          ary = prefix.map(&:to_i).map do |v|
            "#{((v >> 16) & 0xffff).to_s(16)}:#{(v & 0xffff).to_s(16)}"
          end
          pfx = ary.join(':')
          pfx += '::' if prefix.size < (128 / 32)
          "#{IPAddr.new(pfx)}/#{length}"
        end

        # Set prefix from a human-readable string. This method cannot set
        # {#options} field.
        # @param [String] str
        # @return [void]
        def from_human(str)
          ary, len = ary_and_prefix_len_from_str(str)

          self.prefix.clear
          ary.each_with_index do |v, i|
            if i.even?
              self.prefix << v
            else
              self.prefix.last.value = (self.prefix.last.to_i << 16) | v.to_i
            end
          end
          self.length = len
        end

        private

        def ary_and_prefix_len_from_str(str)
          pfx, len = str.split('/')
          len = (len || 128).to_i
          addr = IPv6::Addr.new.from_human(pfx)
          ary_size = (len + 31) / 32
          ary = addr.to_a[0...ary_size * 2]

          [ary, len]
        end
      end

      # Array of {IPv6Prefix}
      # @author Sylvain Daubert
      class ArrayOfIPv6Prefix < BinStruct::Array
        set_of IPv6Prefix
      end
    end
  end
end
