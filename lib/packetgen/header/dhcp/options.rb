# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class DHCP
      
      # Container class for DHCP Options
      # @author Sylvain Daubert
      class Options < Types::Array
        set_of Option
      end
    end
  end
end
