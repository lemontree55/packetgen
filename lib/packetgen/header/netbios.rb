# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    # Module to group all NetBIOS headers
    # @author Sylvain Daubert
    # @since 2.5.1
    module NetBIOS
    end
  end
end

require_relative 'netbios/name'
require_relative 'netbios/session'
