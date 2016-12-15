# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  # Namespace for protocol header classes
  # @author Sylvain Daubert
  module Header

    # Get known header classes
    # @return [Array<Class>]
    def self.all
      constants.map { |sym| const_get sym }.
        select { |klass| klass < Struct && klass < HeaderMethods }
    end
  end
end

require_relative 'header/header_class_methods'
require_relative 'header/header_methods'
require_relative 'header/eth'
require_relative 'header/ip'
require_relative 'header/icmp'
require_relative 'header/arp'
require_relative 'header/ipv6'
require_relative 'header/icmpv6'
require_relative 'header/udp'
