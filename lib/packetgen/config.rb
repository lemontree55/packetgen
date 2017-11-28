# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

require 'socket'
require 'singleton'
require 'network_interface'

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
      begin
        default_iface = Pcap.lookupdev
      rescue PCAPRUB::BindingError
        default_iface = NetworkInterface.interfaces.select { |i| i =~ /lo/ }.first
      end
      @default_iface = default_iface
      @hwaddr = {}
      @ipaddr = {}
      @ip6addr = {}

      NetworkInterface.interfaces.each do |iface|
        addresses = NetworkInterface.addresses(iface)
        @hwaddr[iface] = case RbConfig::CONFIG['target_os']
                  when /darwin/
                    addresses[Socket::AF_LINK][0]['addr'] if addresses[Socket::AF_LINK]
                  else
                    addresses[Socket::AF_PACKET][0]['addr'] if addresses[Socket::AF_PACKET]
                  end
        @ipaddr[iface] = addresses[Socket::AF_INET][0]['addr'] if addresses[Socket::AF_INET]
        if addresses[Socket::AF_INET6]
          @ip6addr[iface] = addresses[Socket::AF_INET6].map { |hsh| hsh['addr'] }
        end
      end
    end

    # Get MAC address for given network interface
    # @param [String,nil] iface network interface. Il +nil+, use default one.
    # @return [String]
    def hwaddr(iface=nil)
      @hwaddr[iface || @default_iface]
    end
    
    # Get IP address for given network interface
    # @param [String,nil] iface network interface. Il +nil+, use default one.
    # @return [String]
    def ipaddr(iface=nil)
      @ipaddr[iface || @default_iface]
    end
        
    # Get IPv6 addresses for given network interface
    # @param [String,nil] iface network interface. Il +nil+, use default one.
    # @return [Array<String>]
    def ip6addr(iface=nil)
      @ip6addr[iface || @default_iface]
    end
  end
end
