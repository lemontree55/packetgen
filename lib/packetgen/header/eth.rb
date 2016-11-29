module PacketGen
  module Header

    # Ethernet header class
    # @author Sylvain Daubert
    class Eth < Struct.new(:dst, :src, :proto, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # Ethernet MAC address, as a group of 6 bytes
      # @author Sylvain Daubert
      class MacAddr < Struct.new(:a0, :a1, :a2, :a3, :a4, :a5)
        include StructFu
        
        # @param [Hash] options
        # @option options [Integer] :a0
        # @option options [Integer] :a1
        # @option options [Integer] :a2
        # @option options [Integer] :a3
        # @option options [Integer] :a4
        # @option options [Integer] :a5
        def initialize(options={})
          super Int8.new(options[:a0]),
                Int8.new(options[:a1]),
                Int8.new(options[:a2]),
                Int8.new(options[:a3]),
                Int8.new(options[:a4]),
                Int8.new(options[:a5])

        end

        # Parse a string to populate MacAddr
        # @param [String] str
        # @return [self]
        def parse(str)
          bytes = str.split(/:/)
          unless bytes.size == 6
            raise ArgumentError, 'not a MAC address'
          end
          self[:a0].read(bytes[0].to_i(16))
          self[:a1].read(bytes[1].to_i(16))
          self[:a2].read(bytes[2].to_i(16))
          self[:a3].read(bytes[3].to_i(16))
          self[:a4].read(bytes[4].to_i(16))
          self[:a5].read(bytes[5].to_i(16))
          self
        end

        # Read a MacAddr from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          return self if str.nil?
          raise ParseError, 'string too short for Eth' if str.size < self.sz
          force_binary str
          [:a0, :a1, :a2, :a3, :a4, :a5].each_with_index do |byte, i|
            self[byte].read str[i, 1]
          end
        end

        [:a0, :a1, :a2, :a3, :a4, :a5].each do |sym|
          class_eval "def #{sym}; self[:#{sym}].to_i; end\n" \
                     "def #{sym}=(v); self[:#{sym}].read v; end"
        end

        # Addr in human readable form (dotted format)
        # @return [String]
        def to_x
          members.map { |m| "#{'%02x' % self[m]}" }.join(':')
        end
      end

      # @param [Hash] options
      def initialize(options={})
        super MacAddr.new.parse(options[:dst] || '00:00:00:00:00:00'),
              MacAddr.new.parse(options[:src] || '00:00:00:00:00:00'),
              Int16.new(options[:proto] || 0),
              StructFu::String.new.read(options[:body])
      end

      # Read a Eth header from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        return self if str.nil?
        raise ParseError, 'string too short for Eth' if str.size < self.sz
        force_binary str
        self[:dst].read str[0, 6]
        self[:src].read str[6, 6]
        self[:proto].read str[12, 2]
        self[:body].read str[14..-1]
        self
      end

      # Get MAC destination address
      # @return [String]
      def dst
        self[:dst].to_x
      end

      # Set MAC destination address
      # @param [String] addr
      # @return [String]
      def dst=(addr)
        self[:dst].parse addr
      end

      # Get MAC source address
      # @return [String]
      def src
        self[:src].to_x
      end

      # Set MAC source address
      # @param [String] addr
      # @return [String]
      def src=(addr)
        self[:src].parse addr
      end

      # Get protocol field
      # @return [Integer]
      def proto
        self[:proto].to_i
      end

      # Set protocol field
      # @param [Integer] proto
      # @return [Integer]
      def proto=(proto)
        self[:proto].value = proto
      end
      
    end
  end
end
