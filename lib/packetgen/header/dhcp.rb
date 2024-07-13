# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # Dynamic Host Configuration Protocol, {https://tools.ietf.org/html/rfc2131
    # RFC 2131}
    #
    # A DHCP header is quite simple. It is composed of:
    # * a {#magic} field ({Types::Int32}) to retrieve it in a BOOTP header,
    # * a, {#options} field ({Options} type, which is a collection of DHCP
    #   options).
    #
    # In PacketGen, a DHCP header is always a secondary header after {BOOTP} one.
    #
    # == Create a DHCP header
    #   # standalone
    #   dhcp = PacketGen::Header::DHCP.new
    #   # in a packet
    #   pkt = PacketGen.gen('IP').add('BOOTP').add('DHCP')
    #   # access to DHCP header
    #   pkt.dhcp      # => PacketGen::Header::DHCP
    #
    # == Add options
    # Options may be added these ways:
    #   dhcp = PacketGen::Header::DHCP.new
    #   # Add a lease_time option
    #   dhcp.options << { type: 'lease_time', value: 3600 }
    #   # Add a domain option. Here, use integer type
    #   dhcp.options << { type: 15, value: 'example.net'}
    #   # Add an end option
    #   dhcp.options << { type: 'end' }
    #   # And finish with padding
    #   dhcp.options << { type: 'pad' }
    # @author Sylvain Daubert
    # @since 2.2.0
    class DHCP < Base; end

    require_relative 'dhcp/option'
    require_relative 'dhcp/options'

    class DHCP < Base
      # DHCP magic value in BOOTP options
      DHCP_MAGIC = 0x63825363

      # @!attribute magic
      #   @return [Integer]
      define_field :magic, Types::Int32, default: 0x63825563
      # @!attribute options
      #   @return [DHCP::Options]
      define_field :options, DHCP::Options

      # differentiate from BOOTP by checking presence of DHCP magic
      # @return [Boolean]
      def parse?
        self.magic == DHCP_MAGIC
      end
    end

    BOOTP.bind DHCP
  end
end
