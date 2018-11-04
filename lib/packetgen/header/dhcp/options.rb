# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DHCP
      # Container class for DHCP Options
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

        def record_from_hash(hsh)
          case hsh[:type]
          when 'pad', 0
            Pad.new
          when 'end', 255
            End.new
          else
            obj_klass = self.class.set_of_klass
            obj_klass.new(hsh)
          end
        end
      end
    end
  end
end
