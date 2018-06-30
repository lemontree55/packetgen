# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DNS

      # DNS Name, defined as a suite of labels. A label is of type {Types::IntString}.
      # @author Sylvain Daubert
      class Name < Types::Array

        # Mask to decode a pointer on another label
        POINTER_MASK = 0xc000

        # @return [DNS]
        attr_accessor :dns

        def initialize
          super
          @pointer = nil
          @pointer_name = nil
        end

        # @!method push(label)
        #  @param [Types::IntString] label
        #  @return [Name] self
        # @!method <<(label)
        #  @param [Types::IntString] label
        #  @return [Name] self

        # Read a set of labels form a dotted string
        # @param [String] str
        # @return [Name] self
        def from_human(str)
          clear
          return self if str.nil?

          str.split('.').each do |label|
            self << Types::IntString.new(string: label)
          end
          self << Types::IntString.new
        end

        # Read a sequence of label from a string
        # @param [String] str binary string
        # @return [Name] self
        def read(str)
          @pointer = nil
          @pointer_name = nil
          clear
          return self if str.nil?

          force_binary str
          start = 0
          while true
            index = str[start, 2].unpack('n').first
            if pointer? index
              # Pointer on another label
              @pointer = str[start, 2]
              break
            else
              label = Types::IntString.new
              label.read(str[start..-1])
              start += label.sz
              self << label
              break if label.length == 0 or str[start..-1].length == 0
            end
          end
          # force resolution of compressed names
          name_from_pointer
          self
        end

        # Get options binary string
        # @return [String]
        def to_s
          super << @pointer.to_s
        end

        # Get a human readable string
        # @return [String]
        def to_human
          ary = map(&:string)
          np = name_from_pointer
          ary << np if np
          str = ary.join('.')
          str.empty? ? '.' : str
        end

        private

        def pointer?(index)
          return false if index.nil?
          index & POINTER_MASK == POINTER_MASK
        end

        def name_from_pointer
          return nil unless @pointer
          return @pointer_name if @pointer_name
          
          index = @pointer.unpack('n').first
          mask = ~POINTER_MASK & 0xffff
          ptr = index & mask
          name = Name.new
          name.dns = @dns
          @pointer_name = name.read(self.dns.to_s[ptr..-1]).to_human
        end

        def record_from_hash(hsh)
          raise NotImplementedError, "not supported by #{self.class}"
        end
      end
    end
  end
end
