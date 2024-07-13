# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Types
    # @abstract Base enum class to handle binary integers with limited
    #   authorized values
    # An {Enum} type is used to handle an {Int} field with limited
    # and named values.
    #
    # == Simple example
    #  enum = Int8Enum.new('low' => 0, 'medium' => 1, 'high' => 2})
    # In this example, +enum+ is a 8-bit field which may take one
    # among three values: +low+, +medium+ or +high+:
    #  enum.value = 'high'
    #  enum.value              # => 2
    #  enum.value = 1
    #  enum.value              # => 1
    #  enum.to_human           # => "medium"
    # Setting an unknown value will raise an exception:
    #  enum.value = 4          # => raise!
    #  enum.value = 'unknown'  # => raise!
    # But {#read} will not raise when reading an outbound value. This
    # to enable decoding (or forging) of bad packets.
    # @since 2.1.3
    # @author Sylvain Daubert
    class Enum < Int
      # @return [Hash]
      attr_reader :enum

      # @param [Hash] enum enumerated values. Default value is taken from
      #   first element unless given.
      # @param [:little,:big,nil] endian
      # @param [Integer,nil] width
      # @param [Integer,nil] default default value
      def initialize(enum, endian=nil, width=nil, default=nil)
        default ||= enum[enum.keys.first]
        super(nil, endian, width, default)
        @enum = enum
      end

      # Setter for value attribute
      # @param [#to_i, String,nil] value value as an Integer or as a String
      #   from enumration
      # @return [Integer]
      # @raise [ArgumentError] String value is unknown
      def value=(value)
        ival = case value
               when NilClass
                 nil
               when ::String
                 raise ArgumentError, "#{value.inspect} not in enumeration" unless @enum.key? value

                 @enum[value]
               else
                 value.to_i
               end
        @value = ival
      end

      # To handle human API: set value from a String
      alias from_human value=

      # Get human readable value (enum name)
      # @return [String]
      def to_human
        @enum.key(to_i) || "<unknown:#{@value}>"
      end

      def format_inspect
        format_str % [to_human, to_i]
      end
    end

    # Enumeration on one byte. See {Enum}.
    # @author Sylvain Daubert
    # @since 2.1.3
    class Int8Enum < Enum
      # @param [Integer] default
      # @param [Hash] enum
      def initialize(enum, default=nil)
        super(enum, nil, 1, default)
        @packstr = { nil => 'C' }
      end
    end

    # Enumeration on 2-byte integer. See {Enum}.
    # @author Sylvain Daubert
    # @since 2.1.3
    class Int16Enum < Enum
      # @param [Hash] enum
      # @param [:big, :little] endian
      # @param [Integer,nil] default default value
      def initialize(enum, endian=:big, default=nil)
        super(enum, endian, 2, default)
        @packstr = { big: 'n', little: 'v' }
      end
    end

    # Enumeration on big endian 2-byte integer. See {Enum}.
    # @author Sylvain Daubert
    # @since 2.1.3
    class Int16beEnum < Int16Enum
      undef endian=

      # @param [Hash] enum
      # @param [Integer,nil] default default value
      def initialize(enum, default=nil)
        super(enum, :big, default)
      end
    end

    # Enumeration on big endian 2-byte integer. See {Enum}.
    # @author Sylvain Daubert
    # @since 2.1.3
    class Int16leEnum < Int16Enum
      undef endian=

      # @param [Hash] enum
      # @param [Integer,nil] default default value
      def initialize(enum, default=nil)
        super(enum, :little, default)
      end
    end

    # Enumeration on 4-byte integer. See {Enum}.
    # @author Sylvain Daubert
    # @since 2.1.3
    class Int32Enum < Enum
      # @param [Hash] enum
      # @param [:big, :little] endian
      # @param [Integer,nil] default default value
      def initialize(enum, endian=:big, default=nil)
        super(enum, endian, 4, default)
        @packstr = { big: 'N', little: 'V' }
      end
    end

    # Enumeration on big endian 4-byte integer. See {Enum}.
    # @author Sylvain Daubert
    # @since 2.1.3
    class Int32beEnum < Int32Enum
      undef endian=

      # @param [Hash] enum
      # @param [Integer,nil] default default value
      def initialize(enum, default=nil)
        super(enum, :big, default)
      end
    end

    # Enumeration on big endian 4-byte integer. See {Enum}.
    # @author Sylvain Daubert
    # @since 2.1.3
    class Int32leEnum < Int32Enum
      undef endian=

      # @param [Hash] enum
      # @param [Integer,nil] default default value
      def initialize(enum, default=nil)
        super(enum, :little, default)
      end
    end
  end
end
