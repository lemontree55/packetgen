# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class SMB
      # SMB strings (UTF-16 little-endian).
      # @author Sylvain Daubert
      class String < Types::CString
        # @param [Hash] options
        # @option options [Integer] :static_length set a static length for this string
        def initialize(option={})
          super
          self.encode('UTF-16LE')
        end
        # @param [::String] str
        # @return [String] self
        def read(str)
          s = str.force_encoding('UTF-16LE')
          s = s[0, @static_length / 2] if @static_length.is_a? Integer
          idx = s.index(+"\x00".encode('UTF-16LE'))
          s = s[0, idx] unless idx.nil?
          self.replace s
          self
        end
      end
    end
  end
end
