require 'network_interface'
require 'socket'

module PacketGen

  # Config class to provide +config+ object to pgconsole
  # @author Sylvain Daubert
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

    # Create a configuration object. If +iface+ is not set, get first network interface.
    # If non exists, use loopback one.
    # @param [String,nil] iface
    def initialize(iface=nil)
      if iface.nil?
        iface = NetworkInterface.interfaces.select { |iface| iface =~ /lo/ }.first
        iface = NetworkInterface.interfaces.first if iface.nil?
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
