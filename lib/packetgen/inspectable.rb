# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  # Module to add common methods to format types when inspecting packets/headers.
  # @author Sylvain Daubert
  # @since 3.1.5
  module Inspectable
    # Format attribute for inspecting
    # @abstract should be overriden by types.
    # @return [String]
    def format_inspect
      to_s.inspect
    end
  end
end
