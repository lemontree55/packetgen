# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # @since 2.2.0
    # @author Kent 'picat' Gruber
    module HTTP
      # @abstract Base class for HTTP headers.
      # @author Kent 'picat' Gruber
      class Headers
        include BinStruct::Structable

        # Underlying Headers data.
        # @return [Hash{String => String}, nil]
        attr_reader :data
        alias to_h data

        def initialize
          @data = {}
        end

        # Populate object from a string or directly from a hash.
        # @param [String, Hash{String=>String}] s_or_h
        # @return [self]
        def read(s_or_h)
          case s_or_h
          when String
            @data = s_or_h.split("\n").filter_map do |h|
              next unless h.include?(':')

              k, v = h.split(':', 2)
              [k, v.strip]
            end.to_h
          when Hash
            @data = s_or_h
          end
          self
        end

        # Get header value from its name
        # @param [String] header header name
        # @return [String] header value
        def [](header)
          data[header]
        end

        # Say if +self+ include +header+ header
        # @param [String] header header name
        # @return [Boolean]
        def header?(header)
          data.key?(header)
        end
        alias has_header? header?

        # Get binary string.
        # @return [String]
        def to_s
          return "\r\n" if @data.nil? || @data.empty?

          d = []
          @data.map do |k, v|
            d << "#{k}: #{v}"
          end
          d.join("\r\n") << "\r\n\r\n"
        end

        # Get a human readable hash.
        # @return [Hash]
        def to_human
          @data
        end

        # Read human-readable data to populate header data.
        # @param [Hash{String=>String}] data
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
      end
    end
  end
end
