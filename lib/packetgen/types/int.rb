# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # Base integer class to handle binary integers
    # @abstract
    # @author Sylvain Daubert
    class Int

      # Integer value
      # @return [Integer]
      attr_accessor :value
      # Integer endianness
      # @return [:little,:big]
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
      # @param [Integer, String] value
      # @return [self]
      def read(value)
        @value = if value.is_a?(Integer)
                   value.to_i
                 else
                   value.to_s.unpack(@packstr[@endian]).first
                 end
        self
      end

      # @abstract
      # @return [::String]
      # @raise [StandardError] This is an abstrat method and must be redefined
      def to_s
        unless defined? @packstr
          raise StandardError, 'PacketGen::Types::Int#to_s is an abstract method'
        end
        [to_i].pack(@packstr[@endian])
      end

      # Convert Int to Integer
      # @return [Integer]
      def to_i
        @value || @default
      end
      alias to_human to_i

      # Convert Int to Float
      # @return [Float]
      def to_f
        to_i.to_f
      end

      # Give size in bytes of self
      # @return [Integer]
      def sz
        to_s.size
      end
    end

    # One byte integer
    # @author Sylvain Daubert
    class Int8 < Int
      # @param [Integer,nil] value
      def initialize(value=nil)
        super(value, nil, 1)
        @packstr = { nil => 'C' }
      end
    end

    # 2-byte integer
    # @author Sylvain Daubert
    class Int16 < Int
      # @param [Integer,nil] value
      # @param [:big, :little] endian
      def initialize(value=nil, endian=:big)
        super(value, endian, 2)
        @packstr = { big: 'n', little: 'v' }
      end
    end

    # big endian 2-byte integer
    # @author Sylvain Daubert
    class Int16be < Int16
      undef endian=
    end

    # little endian 2-byte integer
    # @author Sylvain Daubert
    class Int16le < Int16
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # 3-byte integer
    # @author Sylvain Daubert
    # @since 2.1.4
    class Int24 < Int
      # @param [Integer,nil] value
      # @param [:big, :little] endian
      def initialize(value=nil, endian=:big)
        super(value, endian, 3)
      end

      # Read an 3-byte Int from a binary string or an integer
      # @param [Integer, String] value
      # @return [self]
      def read(value)
        return self if value.nil?
        @value =  if value.is_a?(Integer)
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

    # big endian 3-byte integer
    # @author Sylvain Daubert
    # @since 2.1.4
    class Int24be < Int24
      undef endian=
    end

    # little endian 3-byte integer
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

    # 4-byte integer
    # @author Sylvain Daubert
    class Int32 < Int
      # @param [Integer,nil] value
      # @param [:big, :little] endian
      def initialize(value=nil, endian=:big)
        super(value, endian, 4)
        @packstr = { big: 'N', little: 'V' }
      end
    end

    # big endian 4-byte integer
    # @author Sylvain Daubert
    class Int32be < Int32
      undef endian=
    end

    # little endian 4-byte integer
    # @author Sylvain Daubert
    class Int32le < Int32
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end

    # 8-byte integer
    # @author Sylvain Daubert
    class Int64 < Int
      # @param [Integer,nil] value
      # @param [:big, :little] endian
      def initialize(value=nil, endian=:big)
        super(value, endian, 8)
        @packstr = { big: 'Q>', little: 'Q<' }
      end
    end

    # big endian 8-byte integer
    # @author Sylvain Daubert
    class Int64be < Int64
      undef endian=
    end

    # little endian 8-byte integer
    # @author Sylvain Daubert
    class Int64le < Int64
      # @param [Integer,nil] value
      undef endian=

      # @param [Integer, nil] value
      def initialize(value=nil)
        super(value, :little)
      end
    end
  end
end
