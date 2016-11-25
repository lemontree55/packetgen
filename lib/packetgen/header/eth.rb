module PacketGen
  module Header

    # Ethernet header class
    # @author Sylvain Daubert
    class Eth < Struct.new(:dst, :src, :proto, :body)
      include StructFu
      extend HeaderClassMethods

      # Ethernet MAC address, as a group of 6 bytes
      # @author Sylvain Daubert
      class MacAddr < Struct.new(:a0, :a1, :a2, :a3, :a4, :a5)
        include StructFu
        
        # Parse a string to populate MacAddr
        # @param [String] str
        # @return [self]
        def parse(str)
          bytes = str.split(/:/)
          unless bytes.size == 6
            raise ArgumentError, 'not a MAC address'
          end
          self[:a0] = bytes[0].to_i(16)
          self[:a1] = bytes[1].to_i(16)
          self[:a2] = bytes[2].to_i(16)
          self[:a3] = bytes[3].to_i(16)
          self[:a4] = bytes[4].to_i(16)
          self[:a5] = bytes[5].to_i(16)
          self
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
