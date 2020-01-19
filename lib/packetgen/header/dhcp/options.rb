# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class DHCP
      # Container class for {Option DHCP Options}.
      #
      # == Add DHCP options to an +Options+ instance
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
        set_of Option

        private

        def real_type(obj)
          case obj.type
          when 0
            Pad
          when 1, 3, 4, 5, 6, 7, 8, 9, 28, 41, 42, 44, 45, 50, 54, 65, 69,
               70, 71, 72, 73, 74
            IPAddrOption
          when 53
            Int8Option
          when 57
            Int16Option
          when 51, 58, 59
            Int32Option
          when 255
            End
          else
            Option
          end
        end
      end
    end
  end
end
