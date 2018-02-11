# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # @abstract Base class to define set of {Fields} subclasses.
    # == #record_from_hash
    # Subclasses should define private method +#record_from_hash+. This method
    # is called by {#push} to add an object to the set.
    #
    # A default method is defined by {Array}: it calls constructor of class defined
    # by {.set_of}.
    # @author Sylvain Daubert
    class Array < ::Array

      # Separator used in {#to_human}.
      # May be ovverriden by subclasses
      HUMAN_SEPARATOR = ','

      # Define type of objects in set. Used by {#read} and {#push}.
      # @param [Class] klass
      # @return [void]
      def self.set_of(klass)
        @klass = klass
      end

      # @param [Hash] options
      # @option options [Int] counter Int object used as a counter for this set
      def initialize(options={})
        super()
        @counter = options[:counter]
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
          self.push obj
          str.slice!(0, obj.sz)
          break if @counter and self.size == @counter.to_i
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

      # @abstract depend on private method +#record_from_hash+ which should be
      #   declared by subclasses.
      # Add an object to this array, and increment associated counter, if any
      # @param [Object] obj type depends on subclass
      # @return [Array] self
      def <<(obj)
        push obj
        @counter.read(@counter.to_i + 1) if @counter
        self
      end

      # Delete an object from this array. Update associated counter if any
      # @param [Object] obj
      # @return [Object] deleted object
      def delete(obj)
        deleted = super
        @counter.read(@counter.to_i - 1) if @counter && deleted
        deleted
      end

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

      private

      def record_from_hash(obj)
        obj_klass = self.class.class_eval { @klass }
        if obj_klass
          obj_klass.new(obj)
        else
          raise NotImplementedError, 'class should define #record_from_hash or declare type of elements in set with .set_of'
        end
      end
    end
  end
end
