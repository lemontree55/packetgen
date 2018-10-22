# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

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
    class Array
      include Enumerable

      # Separator used in {#to_human}.
      # May be ovverriden by subclasses
      HUMAN_SEPARATOR = ','

      class <<self
        # Get class set with {#set_of}.
        # @return [Class]
        def set_of_klass
          @klass
        end

        # Define type of objects in set. Used by {#read} and {#push}.
        # @param [Class] klass
        # @return [void]
        # rubocop:disable Naming/AccessorMethodName
        def set_of(klass)
          @klass = klass
        end
        # rubocop:enable Naming/AccessorMethodName
      end

      # @param [Hash] options
      # @option options [Int] counter Int object used as a counter for this set
      def initialize(options={})
        @counter = options[:counter]
        @array = []
      end

      # Initialize array for copy:
      # * duplicate internal array.
      def initialize_copy(_other)
        @array = @array.dup
      end

      # Return the element at +index+.
      # @param [integer] index
      # @return [Object]
      def [](index)
        @array[index]
      end

      def ==(other)
        case other
        when Array
          @array == other.to_a
        else
          @array == other
        end
      end

      # Clear array.
      # @return [void]
      def clear
        @array.clear
      end

      # Clear array. Reset associated counter, if any.
      # @return [void]
      def clear!
        @array.clear
        @counter.read(0) if @counter
      end

      # Delete an object from this array. Update associated counter if any
      # @param [Object] obj
      # @return [Object] deleted object
      def delete(obj)
        deleted = @array.delete(obj)
        @counter.read(@counter.to_i - 1) if @counter && deleted
        deleted
      end

      # Delete element at +index+.
      # @param [Integer] index
      # @return [Object,nil] deleted object
      def delete_at(index)
        deleted = @array.delete_at(index)
        @counter.read(@counter.to_i - 1) if @counter && deleted
        deleted
      end

      # Calls the given block once for each element in self, passing that
      # element as a parameter. Returns the array itself.
      # @return [Array]
      def each
        @array.each { |el| yield el }
      end

      # Return +true+ if contains no element.
      # @return [Booelan]
      def empty?
        @array.empty?
      end

      # Return first element
      # @return [Object]
      def first
        @array.first
      end

      # Return last element.
      # @return [Object]
      def last
        @array.last
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
        @array << obj
        self
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

      # Populate object from a string
      # @param [String] str
      # @return [self]
      def read(str)
        clear
        return self if str.nil?
        return self if @counter && @counter.to_i.zero?
        force_binary str
        klass = self.class.set_of_klass
        until str.empty?
          obj = klass.new.read(str)
          @array << obj
          str.slice!(0, obj.sz)
          break if @counter && self.size == @counter.to_i
        end
        self
      end

      # Get number of element in array
      # @return [Integer]
      def size
        @array.size
      end
      alias length size

      # Get size in bytes
      # @return [Integer]
      def sz
        to_s.size
      end

      # Return an Array
      # @return [::Array]
      def to_a
        @array
      end

      # Get binary string
      # @return [String]
      def to_s
        @array.map(&:to_s).join
      end

      # Get a human readable string
      # @return [String]
      def to_human
        @array.map(&:to_human).join(self.class::HUMAN_SEPARATOR)
      end

      # Force binary encoding for +str+
      # @param [String] str
      # @return [String] binary encoded string
      def force_binary(str)
        PacketGen.force_binary str
      end

      private

      def record_from_hash(obj)
        obj_klass = self.class.set_of_klass
        if obj_klass
          obj_klass.new(obj)
        else
          raise NotImplementedError, 'class should define #record_from_hash or declare type of elements in set with .set_of'
        end
      end
    end

    # Specialized array to handle serie of {Int8}.
    class ArrayOfInt8 < Array
      set_of Int8
    end
    # Specialized array to handle serie of {Int16}.
    class ArrayOfInt16 < Array
      set_of Int16
    end
    # Specialized array to handle serie of {Int16le}.
    class ArrayOfInt16le < Array
      set_of Int16le
    end
    # Specialized array to handle serie of {Int32}.
    class ArrayOfInt32 < Types::Array
      set_of Types::Int32
    end
    # Specialized array to handle serie of {Int32le}.
    class ArrayOfInt32le < Types::Array
      set_of Types::Int32le
    end
  end
end
