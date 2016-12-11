module PacketGen
  module Header

    # TCP header class
    # @author Sylvain Daubert
    class TCP < Struct.new(:sport, :dport, :seq, :ack, :hlen, :reserved,
                           :flags, :wsize, :sum, :urg, :options, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # IP protocol number for TCP
      IP_PROTOCOL = 6

      # @param [Hash] options
      # @option options [Integer] :sport
      # @option options [Integer] :dport
      # @option options [Integer] :seq
      # @option options [Integer] :ack
      # @option options [Integer] :hlen
      # @option options [Integer] :reserved
      # @option options [Integer] :flags
      # @option options [Integer] :wsize
      # @option options [Integer] :sum
      # @option options [Integer] :urg
      # @option options [String] :body
      def initialize(options={})
        super Int16.new(options[:sport]),
              Int16.new(options[:dport]),
              Int32.new(options[:seq] || rand(2**32)),
              Int32.new(options[:ack]),
              options[:hlen] || 5,
              options[:reserved] || 0,
              options[:flags] || 0,
              Int16.new(options[:wsize]),
              Int16.new(options[:sum]),
              Int16.new(options[:urg]),
              TCP::Options.new,
              StructFu::String.new.read(options[:body])
      end

      # Read a TCP header from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        return self if str.nil?
        raise ParseError, 'string too short for TCP' if str.size < self.sz
        force_binary str
        self[:sport].read str[0, 2]
        self[:dport].read str[2, 2]
        self[:seq].read str[4, 4]
        self[:ack].read str[8, 4]
        u16 = str[12, 2].unpack('n').first
        self[:hlen] = u16 >> 12
        self[:reserved] =  (u16 >> 9) & 0x7
        self[:flags] = u16 & 0x1ff
        self[:wsize].read str[14, 2]
        self[:sum].read str[16, 2]
        self[:urg].read str[18, 2]
        self[:options].read str[20, (self[:hlen] - 5) * 4] if self[:hlen] > 5
        self[:body].read str[self[:hlen] * 4..-1]
      end

      # Compute checksum and set +sum+ field
      # @return [Integer]
      def calc_sum
        sum = ip_header(self).pseudo_header_sum
        sum += IP_PROTOCOL
        sum += self.sz
        str = self.to_s
        str << "\x00" if str.length % 2 == 1
        sum += str.unpack('n*').reduce(:+)

        while sum > 0xffff do
          sum = (sum & 0xffff) + (sum >> 16)
        end
        sum = ~sum & 0xffff
        self[:sum].value = (sum == 0) ? 0xffff : sum
      end

      # Compute header length and set +hlen+ field
      # @return [Integer]
      def calc_length
        self[:hlen] = 5 + self[:options].sz / 4
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

      # Getter for seq attribuute
      # @return [Integer]
      def seq
        self[:seq].to_i
      end
      alias :sequence_number :seq

      # Setter for seq attribuute
      # @param [Integer] seq
      # @return [Integer]
      def seq=(seq)
        self[:seq].read seq
      end
      alias :sequence_number= :seq=

      # Getter for ack attribuute
      # @return [Integer]
      def ack
        self[:ack].to_i
      end
      alias :acknowledgment_number :ack

      # Setter for ack attribuute
      # @param [Integer] ack
      # @return [Integer]
      def ack=(ack)
        self[:ack].read ack
      end
      alias :acknowledgment_number= :ack=

      # Getter for wsize attribuute
      # @return [Integer]
      def wsize
        self[:wsize].to_i
      end
      alias :window_size :wsize

      # Setter for wsize attribuute
      # @param [Integer] wsize
      # @return [Integer]
      def wsize=(wsize)
        self[:wsize].read wsize
      end
      alias :window_size= :wsize=

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

      # Getter for urg attribuute
      # @return [Integer]
      def urg
        self[:urg].to_i
      end
      alias :urgent_pointer :urg

      # Setter for urg attribuute
      # @param [Integer] urg
      # @return [Integer]
      def urg=(urg)
        self[:urg].read urg
      end
      alias :urgent_pointer= :urg=

      # Get binary string
      # @return [String]
      def to_s
        ary1 = to_a[0..3]
        ary2 = to_a[7..10]
        u16 = ((self[:hlen] & 0xf) << 12) |
              ((self[:reserved] & 0x7) << 9) |
              (self[:flags] & 0x1ff)
        ary1.map(&:to_s).join << [u16].pack('n') << ary2.map(&:to_s).join
      end
    end

    IP.bind_header TCP, proto: TCP::IP_PROTOCOL
    IPv6.bind_header TCP, next: TCP::IP_PROTOCOL
  end
end

require_relative 'tcp/options'
