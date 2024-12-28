# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require 'socket'
require 'singleton'

module PacketGen
  # Config class to provide +config+ object to pgconsole
  # @author Sylvain Daubert
  # @since 1.4.1
  # @since 2.1.3 Config is singleton
  class Config
    include Singleton

    # Default network interface
    # @return [String]
    attr_reader :default_iface

    def initialize
      @default_iface = PacketGen.default_iface || PacketGen.loopback_iface
      @hwaddr = {}
      @ipaddr = {}
      @ip6addr = {}

      initialize_local_addresses
    end

    # Get MAC address for given network interface
    # @param [String,nil] iface network interface. If +nil+, use default one.
    # @return [String]
    def hwaddr(iface=nil)
      @hwaddr[iface || default_iface]
    end

    # Get IP address for given network interface
    # @param [String,nil] iface network interface. If +nil+, use default one.
    # @return [String]
    def ipaddr(iface=nil)
      @ipaddr[iface || default_iface]
    end

    # Get IPv6 addresses for given network interface
    # @param [String,nil] iface network interface. If +nil+, use default one.
    # @return [Array<String>]
    def ip6addr(iface=nil)
      @ip6addr[iface || default_iface]
    end

    private

    def initialize_local_addresses
      Interfacez.all do |iface_name|
        @hwaddr[iface_name] = Interfacez.mac_address_of(iface_name)
        @ipaddr[iface_name] = Interfacez.ipv4_address_of(iface_name)
        @ip6addr[iface_name] = Interfacez.ipv6_addresses_of(iface_name)
      end
    end
  end
end
