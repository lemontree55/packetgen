# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class DHCPv6
      # Container class for DHCPv6 Options
      #
      # == Add DHCPv6 options to an +Options+ instance
      #   options = PacketGen::Header::DHCP::Options.new
      #   # Add a lease_time option
      #   options << { type: 'lease_time', value: 3600 }
      #   # Add a domain option. Here, use integer type
      #   options << { type: 15, value: 'example.net'}
      #   # Add an end option
      #   options << { type: 'end' }
      #   # And finish with padding
      #   options << { type: 'pad' }
      # @author Sylvain Daubert
      class Options < Types::Array
        set_of DHCPv6::Option

        # Separator used in {#to_human}.
        HUMAN_SEPARATOR = ';'
      end
    end
  end
end
