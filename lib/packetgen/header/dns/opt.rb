# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require_relative 'option'

module PacketGen
  module Header
    class DNS
      # OPT pseudo-RR. Used by Extended DNS (EDNS(0), cf. RFC 6891).
      #
      # a OPT record may contain zero or more {Option options} in its {#rdata}.
      # @author Sylvain Daubert
      # @since 1.3.0
      # @since 3.1.1 {#options} is a {ArrayOfOptions}
      class OPT < RR
        # @!attribute options
        #   @return [ArrayOfOptions]
        define_attr_after :rdata, :options, ArrayOfOptions

        # @param [DNS] dns
        # @param [Hash] options
        # @option options [String] :name domain as a dotted string. Default to +"."+
        # @option options [Integer,String] :type see {TYPES}. Default to +'OPT'+
        # @option options [Integer] :udp_size UDP maximum size. Also +:rrclass+.
        #  Default to 512.
        # @option options [Integer] :ext_rcode
        # @option options [Integer] :version
        # @option options [Boolean] :do DO bit
        # @option options [Integer] :ttl set +ext_rcode+, +version+, +do+ and
        #   +z+ at once
        # @option options [Integer] :rdlength if not provided, automatically set
        #   from +:rdata+ length
        # @option options [String] :rdata
        def initialize(dns, options={})
          opts = { name: '.', rrclass: 512, type: 41 }.merge!(options)
          super(dns, opts)

          self.udp_size = options[:udp_size] if options[:udp_size]
          self.ext_rcode = options[:ext_rcode] if options[:ext_rcode]
          self.version = options[:version] if options[:version]
          self.do = options[:do] unless options[:do].nil?
        end

        # @overload ext_rcode=(value)
        #   Setter for upper 8 bits of extended 12-bit RCODE
        #   @param [Integer] value
        #   @return [Integer]
        # @overload ext_rcode
        #   Getter for upper 8 bits of extended 12-bit RCODE
        #   @return [Integer]
        # @return [Integer]
        def ext_rcode=(value=nil)
          if value
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~(0xff << 24))
            self[:ttl].value |= (value & 0xff) << 24
          end
          (self[:ttl].to_i >> 24) & 0xff
        end
        alias ext_rcode ext_rcode=

        # @overload version=(ver)
        #   Setter EDNS version
        #   @param [Integer] ver
        #   @return [Integer]
        # @overload version
        #   Getter for EDNS version
        #   @return [Integer]
        # @return [Integer]
        def version=(ver=nil)
          if ver
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~(0xff << 16))
            self[:ttl].value |= (ver & 0xff) << 16
          end
          (self[:ttl].to_i >> 16) & 0xff
        end
        alias version version=

        # @overload do=(value)
        #  Setter EDNS do
        #  @param [Boolean] value
        #  @return [Boolean]
        # @overload do?
        #  Getter for EDNS do
        #  @return [Boolean]
        # @return [Boolean]
        def do=(value=nil)
          b = value ? 1 : 0
          unless value.nil?
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~(1 << 15))
            self[:ttl].value |= (b & 1) << 15
          end
          self[:ttl].to_i.anybits?(0x8000)
        end
        alias do? do=

        # @overload z=(value)
        #  @param [Integer] value
        #  @return [Integer]
        # @overload z
        #  @return [Integer]
        # @return [Integer]
        def z=(value=nil)
          if value
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~0x7fff)
            self[:ttl].value |= value & 0x7fff
          end
          self[:ttl].to_i & 0x7fff
        end
        alias z z=

        # @!attribute udp_size
        #  @return [Integer] UDP payload size
        alias udp_size rrclass
        alias udp_size= rrclass=

        # @return [String]
        def human_flags
          do? ? 'do' : 'none'
        end

        # @return [String]
        def to_human
          "#{name} #{human_type} UDPsize:#{udp_size} " \
            "extRCODE:#{ext_rcode} EDNSversion:#{version} flags:#{human_flags} " \
            "options:#{options.empty? ? 'none' : options.to_human}"
        end
      end
    end
  end
end
