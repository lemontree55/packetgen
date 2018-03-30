# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Types

    # This class handles null-terminated strings (aka C strings).
    # @author Sylvain Daubert
    class CString < ::String

      # @param [Hash] options
      # @option options [Integer] :static_length set a static length for this string
      def initialize(options={})
        super()
        @static_length = options[:static_length]
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        s = str.to_s
        if @static_length.is_a? Integer
          s = s[0, @static_length]
        end
        idx = s.index(0.chr)
        s = s[0, idx] unless idx.nil?
        self.replace s
        self
      end

      # get null-terminated string
      # @return [String]
      def to_s
        if @static_length.is_a? Integer
          if self.size >= @static_length
            s = self[0, @static_length]
            s[-1] = 0.chr
            PacketGen.force_binary s
          else
            PacketGen.force_binary(self + "\0" * (@static_length - self.length))
          end
        else
          PacketGen.force_binary(self + 0.chr)
        end
      end

      # @return [Integer]
      def sz
        if @static_length.is_a? Integer
          @static_length
        else
          to_s.size
        end
      end

      # @return [String]
      def to_human
        idx = self.index(0.chr) || self.sz
        self[0, idx]
      end
    end
  end
end
