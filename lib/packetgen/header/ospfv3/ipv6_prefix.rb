# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3

      # Array of 32-bit words.
      # @author Sylvain Daubert
      class ArrayOfInt32 < Types::Array
        set_of Types::Int32
      end

      # This class handles IPv6 prefixes, as defined in RFC 5340 §A.4.1.
      # A IPv6 prefix consists of:
      # * a 8-bit {#length} field (length of the prefix, in bits),
      # * a 8-bit {#options} field, giving prefix capabilities,
      # * a 16-bit {#reserved} field (but it may be used in some LSA),
      # * and an array of 32-bit words to encode prefix itself ({#prefix}). This
      #   array consumes ((PrefixLength + 31) / 32) 32-bit words.
      # @author Sylvain Daubert
      class IPv6Prefix < Types::Fields
        # @!attribute length
        #  Prefix length, in bits
        #  @return [Integer]
        define_field :length, Types::Int8
        # @!attribute options
        #  Prefix capabilities
        #  @return [Options]
        define_field :options, Types::Int8
        # @!attribute reserved
        #  Reserved field in most of LSA types.
        #  @return [Integer]
        define_field :reserved, Types::Int16
        # @!attribute prefix
        #  IPv6 Prefix
        #  @return [Prefix]
        define_field :prefix, ArrayOfInt32

        # @!attribute dn_opt
        #  This bit controls an inter-area-prefix-LSAs or AS-external-LSAs
        #  re-advertisement in a VPN environment.
        #  @return [Boolean]
        # @!attribute p_opt
        #  The "propagate" bit.  Set on NSSA area prefixes that should be
        #  readvertised by the translating NSSA area border.
        #  @return [Boolean]
        # @!attribute la_opt
        #  The "local address" capability bit.  If set, the prefix is
        #  actually an IPv6 interface address of the Advertising Router.
        #  @return [Boolean]
        # @!attribute nu_opt
        #  The "no unicast" capability bit.  If set, the prefix should be
        #  excluded from IPv6 unicast calculations.
        #  @return [Boolean]
        define_bit_fields_on :options, :zz, 3, :dn_opt, :p_opt, :z, :la_opt, :nu_opt

        # Get human-readable prefix
        # @return [String]
        def to_human
          ary = prefix.map(&:to_i).map do |v|
            "#{((v>>16) & 0xffff).to_s(16)}:#{(v & 0xffff).to_s(16)}"
          end
          pfx = ary.join(':')
          pfx += '::' if prefix.size < (128/32)
          "#{IPAddr.new(pfx).to_s}/#{length}"
        end
        
        # Set prefix from a human-readable string. This method cannot set
        # {#options} field.
        # @param [String] str
        # @return [void]
        def from_human(str)
          pfx, len = str.split('/')
          len = (len || 128).to_i
          addr = IPv6::Addr.new.from_human(pfx)
          ary_size = (len + 31) / 32
          ary = addr.to_a[0...ary_size*2]
          self.prefix.clear
          ary.each_with_index do |v, i|
            if i % 2 == 0
              self.prefix << v
            else
              self.prefix.last.value = (self.prefix.last.to_i << 16) | v.to_i
            end
          end
          self.length = len
        end
      end
      
      # Array of {IPv6Prefix}
      # @author Sylvain Daubert
      class ArrayOfIPv6Prefix < Types::Array
        set_of IPv6Prefix
      end
    end
  end
end
