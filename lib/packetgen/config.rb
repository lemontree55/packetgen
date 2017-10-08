# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

require 'network_interface'
require 'socket'

module PacketGen

  # Config class to provide +config+ object to pgconsole
  # @author Sylvain Daubert
  # @author Kent 'picat' Gruber
  class Config

    # Default network interface
    # @return [String]
    attr_reader :iface
    # MAC address of default interface
    # @return [String]
    attr_reader :hwaddr
    # IP address of default interface
    # @return [String]
    attr_reader :ipaddr
    # IPv6 address of default interface
    # @return [String]
    attr_reader :ip6addr

    # Create a configuration object. If +iface+ is not set,
    # attempt to find it automatically or default to the
    # first available loopback interface.
    # @param [String,nil] iface
    def initialize(iface=nil)
      if iface.nil?
        begin
          iface = Pcap.lookupdev
        rescue PCAPRUB::BindingError
          iface = NetworkInterface.interfaces.select { |i| i =~ /lo/ }.first
        end
      end
      @iface = iface

      addresses = NetworkInterface.addresses(iface)
      @hwaddr = case RbConfig::CONFIG['target_os']
                when /darwin/
                  addresses[Socket::AF_LINK][0]['addr'] if addresses[Socket::AF_LINK]
                else
                  addresses[Socket::AF_PACKET][0]['addr'] if addresses[Socket::AF_PACKET]
                end
      @ipaddr = addresses[Socket::AF_INET][0]['addr'] if addresses[Socket::AF_INET]
      @ip6addr = addresses[Socket::AF_INET6][0]['addr'] if addresses[Socket::AF_INET6]
    end
  end
end
