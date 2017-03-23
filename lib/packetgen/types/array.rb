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

      # Separator used in {#to_human}.
      # May be ovverriden by subclasses
      HUMAN_SEPARATOR = ','

      # Define type of objects in set. Used by {#read}.
      # @param [Class] klass
      # @return [void]
      def self.set_of(klass)
        @klass = klass
      end

      # Populate object from a string
      # @param [String] str
      # @return [self]
      def read(str)
        clear
        return self if str.nil?
        force_binary str
        klass = self.class.class_eval { @klass }
        while str.length > 0
          obj = klass.new.read(str)
          self << obj
          str.slice!(0, obj.sz)
        end
        self
      end

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
        map(&:to_human).join(self.class::HUMAN_SEPARATOR)
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
