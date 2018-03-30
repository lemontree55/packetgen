# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DNS

      # DNS option
      # @author Sylvain Daubert
      class Option < Types::TLV

        # Force {#type} and {#length} fields to be {Types::Int16}
        # @see TLV#initialize
        def initialize(options={})
          super options.merge!(t: Types::Int16, l: Types::Int16)
        end
      end
    end
  end
end
