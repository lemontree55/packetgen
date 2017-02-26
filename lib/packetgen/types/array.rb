# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # @abstract
    # Array supporting some fields methods
    # @author Sylvain Daubert
    class Array < ::Array

      # @abstract depend on private method +#record_from_hash+ which should be
      #   declared by subclasses.
      # Add an object to this array
      # @param [Object] obj type depends on subclass
      # @return [Array] self
      def push(obj)
        obj = case obj
              when Hash
                record_from_hash obj
              else
                obj
              end
        super(obj)
      end
      alias :<< :push

      # Get binary string
      # @return [String]
      def to_s
        map(&:to_s).join
      end

      # Get a human readable string
      # @return [String]
      def to_human
        map(&:to_human).join(',')
      end

      # Get size in bytes
      # @return [Integer]
      def sz
        to_s.size
      end

      # Force binary encoding for +str+
      # @param [String] str
      # @return [String] binary encoded string
      def force_binary(str)
        PacketGen.force_binary str
      end
    end
  end
end
