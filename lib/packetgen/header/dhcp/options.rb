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

        private

        def record_from_hash(hsh)
          case hsh[:type]
          when 'pad', 0
            Pad.new
          when 'end', 255
            End.new
          else
            obj_klass = self.class.class_eval { @klass }
            obj_klass.new(hsh)
          end
        end
      end
    end
  end
end
