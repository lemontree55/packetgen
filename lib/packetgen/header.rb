# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  # Namespace for protocol header classes
  # == Add a foreign header class
  # Since v1.1.0, PacketGen permits adding you own header classes.
  # First, define the new header class. By example:
  #  module MyModule
  #    class MyHeader < PacketGen::Header::Base
  #      define_field :field1, PacketGen::Types::Int32
  #      define_field :field2, PacketGen::Types::Int32
  #    end
  #   end
  # Then, class must be declared to PacketGen:
  #  PacketGen::Header.add_class MyModule::MyHeader
  # Finally, bindings must be declared:
  #  # bind MyHeader as IP protocol number 254 (needed by Packet#parse and Packet#add)
  #  PacketGen::Header::IP.bind_header MyModule::MyHeader, protocol: 254
  # And use it:
  #  pkt = Packet.gen('IP').add('MyHeader', field1: 0x12345678)
  #  pkt.myheader.field2.read 0x01
  # @author Sylvain Daubert
  module Header
    # @private snap length for PCAPRUB
    PCAP_SNAPLEN = 0xffff
    # @private promiscuous (or not) for PCAPRUB
    PCAP_PROMISC = false
    # @private timeout for PCAPRUB
    PCAP_TIMEOUT = 1

    @added_header_classes = {}

    class << self
      # List all available headers.
      # @return [Array<Class>]
      def all
        return @header_classes if @header_classes
        @header_classes = @added_header_classes.values
      end
      alias list all

      # Add a foreign header class to known header classes. This is
      # needed by {Packet.gen} and {Packet#add}.
      # @param [Class] klass a header class
      # @return [void]
      # @since 1.1.0
      def add_class(klass)
        protocol_name = klass.new.protocol_name
        @added_header_classes[protocol_name] = klass
        @header_classes = nil
      end

      # Remove a foreign header (previously added by {.add_header_class}
      # from known header classes.
      # @param [Class] klass
      # @return [void]
      # @since 1.1.0
      def remove_class(klass)
        protocol_name = klass.new.protocol_name
        @added_header_classes.delete protocol_name
        @header_classes = nil
      end

      # Get header class from its name
      # @param [String] name
      # @return [Class,nil]
      # @since 1.1.0
      def get_header_class_by_name(name)
        if Header.const_defined? name
          Header.const_get name
        else
          @added_header_classes[name]
        end
      end
    end
  end
end

require_relative 'header/crypto'
require_relative 'header/base'
require_relative 'header/eth'
require_relative 'header/dot11'
require_relative 'header/llc'
require_relative 'header/dot1q'
require_relative 'header/dot1x'
require_relative 'header/ip'
require_relative 'header/icmp'
require_relative 'header/arp'
require_relative 'header/ipv6'
require_relative 'header/icmpv6'
require_relative 'header/gre'
require_relative 'header/udp'
require_relative 'header/tcp'
require_relative 'header/eap'
require_relative 'header/esp'
require_relative 'header/ike'
require_relative 'header/dns'
require_relative 'header/asn1_base'
require_relative 'header/snmp'
require_relative 'header/bootp'
require_relative 'header/dhcp'
require_relative 'header/dhcpv6'
require_relative 'header/http'
require_relative 'header/tftp'
require_relative 'header/igmp'
require_relative 'header/igmpv3'
require_relative 'header/mld'
require_relative 'header/mldv2'
require_relative 'header/ospfv2'
require_relative 'header/ospfv3'
require_relative 'header/netbios'
require_relative 'header/smb'
require_relative 'header/mdns'
