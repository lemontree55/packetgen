# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class DHCPv6
      # Container class for DHCPv6 {Option options}.
      #
      # @example Add DHCPv6 options to an +Options+ instance
      #   options = PacketGen::Header::DHCPv6::Options.new
      #   # Add an ElapsedTime option
      #   options << { type: 'ElapsedTime', value: 3600 }
      #   # Add a ClientID. Here, use integer type
      #   duid = PacketGen::Header::DHCPv6::DUID_LL.new(link_addr: '08:00:27:fe:8f:95')
      #   options << { type: 1, duid: duid }
      # @author Sylvain Daubert
      class Options < BinStruct::Array
        set_of DHCPv6::Option

        # Separator used in +#to_human+.
        HUMAN_SEPARATOR = ';'

        private

        def real_type(opt)
          real_klass = Option.subclasses[opt.type]
          real_klass.nil? ? Option : real_klass
        end
      end
    end
  end
end
