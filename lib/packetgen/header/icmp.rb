module PacketGen
  module Header

    # ICMP header class
    # @author Sylvain Daubert
    class ICMP < Struct.new(:type, :code, :sum, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # ICMP internet protocol number
      IP_PROTOCOL = 1

      # @param [Hash] options
      # @option options [Integer] :type
      # @option options [Integer] :code
      # @option options [Integer] :sum
      # @option options [String] :body
      def initialize(options={})
        super Int8.new(options[:type]),
              Int8.new(options[:code]),
              Int16.new(options[:sum]),
              StructFu::String.new.read(options[:body])
      end

      # Read a ICMP header from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        return self if str.nil?
        raise ParseError, 'string too short for ICMP' if str.size < self.sz
        force_binary str
        self[:type].read str[0, 1]
        self[:code].read str[1, 1]
        self[:sum].read str[2, 2]
        self[:body].read str[4..-1]
      end

      # Compute checksum and set +sum+ field
      # @return [Integer]
      def calc_sum
        sum = (type << 8) | code

        payload = body.to_s
        payload << "\x00" unless payload.size % 2 == 0
        payload.unpack('n*').each { |x| sum += x }

        while sum > 0xffff do
          sum = (sum & 0xffff) + (sum >> 16)
        end
        sum = ~sum & 0xffff
        self[:sum].value = (sum == 0) ? 0xffff : sum
      end

      # Getter for type attribute
      # @return [Integer]
      def type
        self[:type].to_i
      end

      # Setter for type attribute
      # @param [Integer] type
      # @return [Integer]
      def type=(type)
        self[:type].value = type
      end

      # Getter for code attribute
      # @return [Integer]
      def code
        self[:code].to_i
      end

      # Setter for code attribute
      # @param [Integer] code
      # @return [Integer]
      def code=(code)
        self[:code].value = code
      end

      # Getter for sum attribute
      # @return [Integer]
      def sum
        self[:sum].to_i
      end

      # Setter for sum attribute
      # @param [Integer] sum
      # @return [Integer]
      def sum=(sum)
        self[:sum].value = sum
      end
    end

    IP.bind_header ICMP, protocol: ICMP::IP_PROTOCOL
  end
end
