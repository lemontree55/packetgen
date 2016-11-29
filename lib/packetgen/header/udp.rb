module PacketGen
  module Header

    # UDP header class
    # @author Sylvain Daubert
    class UDP < Struct.new(:sport, :dport, :length, :sum, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # IP protocol number for UDP
      IP_PROTOCOL = 17

      # @param [Hash] options
      # @option options [Integer] :sport source port
      # @option options [Integer] :dport destination port
      # @option options [Integer] :length UDP length. Default: calculated
      # @option options [Integer] :sum. UDP checksum. Default: 0
      def initialize(options={})
        super Int16.new(options[:sport]),
              Int16.new(options[:dport]),
              Int16.new(options[:length]),
              Int16.new(options[:sum]),
              StructFu::String.new.read(options[:body])
        unless options[:length]
          calc_length
        end
      end

      # Compute checksum and set +sum+ field
      # @return [Integer]
      def calc_sum
        ip = ip_header(self)
        sum = ip[:src].to_i >> 16
        sum += ip[:src].to_i & 0xffff
        sum += ip[:dst].to_i >> 16
        sum += ip[:dst].to_i & 0xffff
        sum += IP_PROTOCOL
        sum += length
        sum += sport
        sum += dport
        sum += length
        payload = body.to_s
        payload << "\x00" unless payload.size % 2 == 0
        payload.unpack('n*').each { |x| sum += x }

        while sum > 0xffff do
          sum = (sum & 0xffff) + (sum >> 16)
        end
        sum = ~sum & 0xffff
        self[:sum].value = (sum == 0) ? 0xffff : sum
      end

      # Compute length and set +length+ field
      # @return [Integer]
      def calc_length
        self[:length].value = self.sz
      end

      # Getter for source port
      # @return [Integer]
      def sport
        self[:sport].to_i
      end
      alias :source_port :sport

      # Setter for source port
      # @param [Integer] port
      # @return [Integer]
      def sport=(port)
        self[:sport].read port
      end
      alias :source_port= :sport=

      # Getter for destination port
      # @return [Integer]
      def dport
        self[:dport].to_i
      end
      alias :destination_port :dport

      # Setter for destination port
      # @param [Integer] port
      # @return [Integer]
      def dport=(port)
        self[:dport].read port
      end
      alias :destination_port= :dport=

      # Getter for length attribuute
      # @return [Integer]
      def length
        self[:length].to_i
      end

      # Setter for length attribuute
      # @param [Integer] port
      # @return [Integer]
      def length=(len)
        self[:length].read len
      end

      # Getter for sum attribuute
      # @return [Integer]
      def sum
        self[:sum].to_i
      end

      # Setter for sum attribuute
      # @param [Integer] sum
      # @return [Integer]
      def sum=(sum)
        self[:sum].read sum
      end
    end

    IP.bind_header UDP, proto: UDP::IP_PROTOCOL
  end
end
