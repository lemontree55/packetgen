# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require 'socket'

module PacketGen
  # Module handling some helper methods for well_known protocols
  # @author Sylvain Daubert
  # @since 2.1.2
  module Proto
    # @private cache information used by {.getprotobyname} and
    #  {.getprotobynumber}
    def self.prepare_cache
      proto_constants = Socket.constants.grep(/IPPROTO_/)
      @cache = {}
      proto_constants.each do |const_sym|
        name = const_sym.to_s[8..].downcase
        number = Socket.const_get(const_sym)
        @cache[name] = number
      end
    end
    prepare_cache

    # Get protocol number from its name
    # @param [String] name
    # @return [Integer,nil] return nil for unknown protocol names
    # @example
    #   PacketGen::Proto.getprotobyname('tcp') #=> 6
    def self.getprotobyname(name)
      @cache[name]
    end

    # Get protocol name from its number
    # @param [Integer] num
    # @return [String,nil] return nil for unknown protocol numbers
    # @example
    #   PacketGen::Proto.getprotobynumber(6) #=> 'tcp'
    def self.getprotobynumber(num)
      @cache.key(num)
    end
  end
end
