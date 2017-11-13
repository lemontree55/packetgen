# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # @abstract Base class for HTTP headers.
    # @author Kent 'picat' Gruber
    class HTTPHeaders
      def initialize
        @data = nil
      end
      
      # Populate object from a string or directly from a hash.
      # @param [String, Hash]
      # @return [PacketGen::Types::HTTPHeaders]
      def read(s_or_h)
        case s_or_h.class.to_s # it, uh ... works
        when "String"
          @data = s_or_h.split("\n").map { |h| k, v = h.split(":", 2); [k.downcase.gsub("-", "_").to_sym, v.strip] }.to_h
        when "Hash"
          @data = s_or_h
        end
        self
      end

      # Get binary string
      # @return [String]
      def to_s
        return "\r\n\r\n" if @data.nil? || @data.empty?
        @data.map do |k, v|
          k = k.to_s.split("_")
          if k == ["dnt"] || k == ["te"]
            k = k.map(&:upcase)
          else
            k = k.map(&:capitalize)
          end
          k = k.join("-")
          k << ": " << v
          k
        end.join("\r\n") << "\r\n\r\n"
      end

      # Get a human readable string
      # @return [Hash]
      def to_human
        @data
      end

      # Shorcut to the underlying HTTPHeaders data or nil.
      # @return [Hash, nil]
      def data
        @data
      end
    end
  end
end
