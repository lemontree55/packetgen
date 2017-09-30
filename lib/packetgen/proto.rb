# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'socket'

module PacketGen

  # Module handling some helper methods for protocols
  # @author Sylvain Daubert
  # @since 2.1.2
  module Proto

    # @private cache information used by {.getprotobyname} and
    #  {.getprotobynumber}
    def self.prepare_cache
      proto_constants = Socket.constants.grep(/IPPROTO_/)
      @cache = {}
      proto_constants.each do |const_sym|
        name = const_sym.to_s[8..-1].downcase
        number = Socket.const_get(const_sym)
        @cache[name] = number
      end
    end
    prepare_cache

    # Get protocol number from its name
    # @param [String] name
    # @return [Integer,nil] return nil for unknown protocol names
    def self.getprotobyname(name)
      @cache[name]
    end

    # Get protocol name from its number
    # @param [Integer] number
    # @return [String,nil] return nil for unknown protocol numbers
    def self.getprotobynumber(num)
      @cache.key(num)
    end
  end
end
