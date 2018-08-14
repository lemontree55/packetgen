# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

require 'socket'
require 'singleton'
require 'interfacez'

module PacketGen
  # Config class to provide +config+ object to pgconsole
  # @author Sylvain Daubert
  # @author Kent 'picat' Gruber
  # @since 1.4.1
  # @since 2.1.3 Config is singleton
  class Config
    include Singleton

    # Default network interface
    # @return [String]
    attr_reader :default_iface

    def initialize
      @default_iface = Interfacez.default || Interfacez.loopback
      @hwaddr = {}
      @ipaddr = {}
      @ip6addr = {}

      Interfacez.all do |iface_name|
        @hwaddr[iface_name] = Interfacez.mac_address_of(iface_name)
        @ipaddr[iface_name] = Interfacez.ipv4_address_of(iface_name)
        @ip6addr[iface_name] = Interfacez.ipv6_addresses_of(iface_name)
      end
    end

    # Get MAC address for given network interface
    # @param [String,nil] iface network interface. If +nil+, use default one.
    # @return [String]
    def hwaddr(iface=nil)
      @hwaddr[iface || @default_iface]
    end

    # Get IP address for given network interface
    # @param [String,nil] iface network interface. If +nil+, use default one.
    # @return [String]
    def ipaddr(iface=nil)
      @ipaddr[iface || @default_iface]
    end

    # Get IPv6 addresses for given network interface
    # @param [String,nil] iface network interface. If +nil+, use default one.
    # @return [Array<String>]
    def ip6addr(iface=nil)
      @ip6addr[iface || @default_iface]
    end
  end
end
