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
          self[:a0] = bytes[0]
          self[:a1] = bytes[1]
          self[:a2] = bytes[2]
          self[:a3] = bytes[3]
          self[:a4] = bytes[4]
          self[:a5] = bytes[5]
          self
        end

        # Addr in human readable form (dotted format)
        # @return [String]
        def to_x
          members.map { |m| "#{'%02x' % self[m]}" }.join(':')
        end
      end

      def initialize(options={})
        super MacAddr.parse(options[:dst]),
              MacAddr.parse(options[:src]),
              Int16.new(options[:proto] || 0),
              StructFu::String.new.read(args[:body])
      end
    end
  end
end
