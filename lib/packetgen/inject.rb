# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require_relative 'pcaprub_wrapper'

module PacketGen
  # Module to inject packets on wire
  # @author Sylvain Daubert
  # @api private
  # @since 3.1.4
  module Inject
    # Inject given data onto wire
    # @param [String] iface interface name
    # @param [String,Packet,Header::Base] data to inject
    # @return [void]
    def self.inject(iface:, data:)
      PCAPRUBWrapper.inject(iface: iface, data: data.to_s)
    end
  end
end
