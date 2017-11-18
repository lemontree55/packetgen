# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    module HTTP 
      # @abstract Base class for HTTP headers.
      # @author Kent 'picat' Gruber
      class Headers
        def initialize
          @data = nil
        end

        # Populate object from a string or directly from a hash.
        # @param [String, Hash]
        # @return [self]
        def read(s_or_h)
          case s_or_h
          when String
            @data = s_or_h.split("\n").map do |h| 
              k, v = h.split(":", 2)
              [k, v.strip] 
            end.to_h
          when Hash
            @data = s_or_h
          end
          self
        end

        # Get binary string
        # @return [String]
        def to_s
          return "\r\n\r\n" if @data.nil? || @data.empty?
          @data.map do |k, v|
            k << ": " << v
          end.join("\r\n") << "\r\n\r\n"
        end

        # Get a human readable string
        # @return [Hash]
        def to_human
          @data
        end

        # Read human-readable data to populate header data.
        # @param [String, Hash]
        # @return [self]
        def from_human(data)
          read(data)
        end

        # Check if any headers were given.
        # @return [Boolean]
        def given?
          return true unless @data.nil? || @data.empty?
          false
        end

        # Shorcut to the underlying HTTPHeaders data or nil.
        # @return [Hash, nil]
        def data
          @data
        end
      end
    end
  end
end

