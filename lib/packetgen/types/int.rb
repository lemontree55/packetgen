# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types
    # Base integer class to handle binary integers
    # @abstract
    # @author Sylvain Daubert
    # @since 3.4.0 support native endianess
    class Int
      include Fieldable

      # Integer value
      # @return [Integer]
      attr_accessor :value
      # Integer endianness
      # @return [:little,:big,:native]
      # @since 3.4.0 add :native
      attr_accessor :endian
      # Integer size, in bytes
      # @return [Integer]
      attr_accessor :width
      # Integer default value
      # @return [Integer]
      attr_accessor :default

      # @param [Integer,nil] value
      # @param [:little,:big,nil] endian
      # @param [Integer,nil] width
      # @param [Integer] default
      def initialize(value=nil, endian=nil, width=nil, default=0)
        @value = value
        @endian = endian
        @width = width
        @default = default
      end

      # @abstract
      # Read an Int from a binary string or an integer
      # @param [Integer, #to_s] value
      # @return [self]
      # @raise [ParseError] when reading +#to_s+ objects with abstract Int class.
      def read(value)
        @value = if value.is_a?(Integer)
                   value.to_i
                 elsif defined? @packstr
                   value.to_s.unpack1(@packstr[@endian])
                 else
                   raise ParseError, 'Int#read is abstract and cannot read'
                 end
        self
      end

      # @abstract
      # @return [::String]
      # @raise [ParseError] This is an abstrat method and must be redefined
      def to_s
        raise ParseError, 'PacketGen::Types::Int#to_s is an abstract method' unless defined? @packstr

        [to_i].pack(@packstr[@endian])
      end

      # Convert Int to Integer
      # @return [Integer]
      def to_i
        @value || @default
      end
      alias to_human to_i
      alias from_human value=

      # Convert Int to Float
      # @return [Float]
      def to_f
        to_i.to_f
      end

      # Give size in bytes of self
      # @return [Integer]
      def sz
        width
      end

      # Format Int type when inspecting header or packet
      # @return [String]
      def format_inspect
        format_str % [to_i.to_s, to_i]
      end

      # Return the number of bits used to encode this Int
      # @return [Integer]
      # @since 3.2.1
      def nbits
        width * 8
      end

      private

      def format_str
        "%-16s (0x%0#{width * 2}x)"
      end
    end

    # One byte unsigned integer
    # @author Sylvain Daubert
    class Int8 < Int
      # @param [Integer,nil] value
      def initialize(value=nil)
        super(value, nil, 1)
        @packstr = { nil => 'C' }
      end
    end

    # One byte signed integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt8 < Int
      # @param [Integer,nil] value
      def initialize(value=nil)
        super(value, nil, 1)
        @packstr = { nil => 'c' }
      end
    end

    # 2-byte unsigned integer
    # @author Sylvain Daubert
    class Int16 < Int
      # @param [Integer,nil] value
      # @param [:big, :little, :native] endian
      def initialize(value=nil, endian=:big)
        super(value, endian, 2)
        @packstr = { big: 'n', little: 'v', native: 'S' }
      end
    end

    # big endian 2-byte unsigned integer
    # @author Sylvain Daubert
    class Int16be < Int16
      undef endian=
    end

    # little endian 2-byte unsigned integer
    # @author Sylvain Daubert
    class Int16le < Int16
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # native endian 2-byte unsigned integer
    # @author Sylvain Daubert
    # @since 3.4.0
    class Int16n < Int16
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :native)
      end
    end

    # 2-byte signed integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt16 < Int16
      # @param [Integer,nil] value
      # @param [:big, :little] endian
      def initialize(value=nil, endian=:big)
        super
        @packstr = { big: 's>', little: 's<', native: 's' }
      end
    end

    # big endian 2-byte signed integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt16be < SInt16
      undef endian=
    end

    # little endian 2-byte signed integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt16le < SInt16
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # native endian 2-byte signed integer
    # @author Sylvain Daubert
    # @since 3.4.0
    class SInt16n < SInt16
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :native)
      end
    end

    # 3-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.1.4
    class Int24 < Int
      # @param [Integer,nil] value
      # @param [:big, :little, :native] endian
      def initialize(value=nil, endian=:big)
        if endian == :native
          endian = if [1].pack('S').unpack1('n') == 1
                     :big
                   else
                     :little
                   end
        end
        super(value, endian, 3)
      end

      # Read an 3-byte Int from a binary string or an integer
      # @param [Integer, String] value
      # @return [self]
      def read(value)
        return self if value.nil?

        @value = if value.is_a?(Integer)
                   value.to_i
                 else
                   up8 = down16 = 0
                   if @endian == :big
                     up8, down16 = value.to_s.unpack('Cn')
                   else
                     down16, up8 = value.to_s.unpack('vC')
                   end
                   (up8 << 16) | down16
                 end
        self
      end

      # @return [::String]
      def to_s
        up8 = to_i >> 16
        down16 = to_i & 0xffff
        if @endian == :big
          [up8, down16].pack('Cn')
        else
          [down16, up8].pack('vC')
        end
      end
    end

    # big endian 3-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.1.4
    class Int24be < Int24
      undef endian=
    end

    # little endian 3-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.1.4
    class Int24le < Int24
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # native endian 3-byte unsigned integer
    # @author Sylvain Daubert
    # @since 3.4.0
    class Int24n < Int24
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :native)
      end
    end

    # 4-byte unsigned integer
    # @author Sylvain Daubert
    class Int32 < Int
      # @param [Integer,nil] value
      # @param [:big, :little, :native] endian
      def initialize(value=nil, endian=:big)
        super(value, endian, 4)
        @packstr = { big: 'N', little: 'V', native: 'L' }
      end
    end

    # big endian 4-byte unsigned integer
    # @author Sylvain Daubert
    class Int32be < Int32
      undef endian=
    end

    # little endian 4-byte unsigned integer
    # @author Sylvain Daubert
    class Int32le < Int32
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # native endian 4-byte unsigned integer
    # @author Sylvain Daubert
    # @since 3.4.0
    class Int32n < Int32
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :native)
      end
    end

    # 4-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt32 < Int32
      # @param [Integer,nil] value
      # @param [:big, :little] endian
      def initialize(value=nil, endian=:big)
        super
        @packstr = { big: 'l>', little: 'l<', native: 'l' }
      end
    end

    # big endian 4-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt32be < SInt32
      undef endian=
    end

    # little endian 4-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt32le < SInt32
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # native endian 4-byte unsigned integer
    # @author Sylvain Daubert
    # @since 3.4.0
    class SInt32n < SInt32
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :native)
      end
    end

    # 8-byte unsigned integer
    # @author Sylvain Daubert
    class Int64 < Int
      # @param [Integer,nil] value
      # @param [:big, :little, :native] endian
      def initialize(value=nil, endian=:big)
        super(value, endian, 8)
        @packstr = { big: 'Q>', little: 'Q<', native: 'Q' }
      end
    end

    # big endian 8-byte unsigned integer
    # @author Sylvain Daubert
    class Int64be < Int64
      undef endian=
    end

    # little endian 8-byte unsigned integer
    # @author Sylvain Daubert
    class Int64le < Int64
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # native endian 8-byte unsigned integer
    # @author Sylvain Daubert
    # @since 3.4.0
    class Int64n < Int64
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :native)
      end
    end

    # 8-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt64 < Int64
      # @param [Integer,nil] value
      # @param [:big, :little, :native] endian
      def initialize(value=nil, endian=:big)
        super
        @packstr = { big: 'q>', little: 'q<', native: 'q' }
      end
    end

    # big endian 8-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt64be < SInt64
      undef endian=
    end

    # little endian 8-byte unsigned integer
    # @author Sylvain Daubert
    # @since 2.8.2
    class SInt64le < SInt64
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # native endian 8-byte unsigned integer
    # @author Sylvain Daubert
    # @since 3.4.0
    class SInt64n < SInt64
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :native)
      end
    end
  end
end
