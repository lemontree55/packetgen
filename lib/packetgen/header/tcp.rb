module PacketGen
  module Header

    # TCP header class
    #
    # == Create a TCP header
    #  # standalone
    #  tcph = PacketGen::Header::TCP.new
    #  # in a IP packet
    #  pkt = PacketGen.gen('IP').add('TCP')
    #  # access to TCP header
    #  pkt.tcp   # => PacketGen::Header::TCP
    #
    # == TCP attributes
    #  tcph.sport = 4500
    #  tcph.dport = 80
    #  tcph.seq = 43
    #  tcph.ack = 0x45678925
    #  tcph.wsize = 0x240
    #
    # == Flags
    # TODO
    #
    # == Options
    # {#options} TCP attribute is a {Options}. {Option} may added to it:
    #  tcph.options << PacketGen::Header::TCP::MSS.new(1250)
    # Another way is to use {Options#add}:
    #  tcph.options.add 'MSS', 1250
    # @author Sylvain Daubert
    class TCP < Struct.new(:sport, :dport, :seqnum, :acknum, :data_offset, :reserved,
                           :flags, :window, :sum, :urg_pointer, :options, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # IP protocol number for TCP
      IP_PROTOCOL = 6

      # @param [Hash] options
      # @option options [Integer] :sport
      # @option options [Integer] :dport
      # @option options [Integer] :seqnum
      # @option options [Integer] :acknum
      # @option options [Integer] :data_offset
      # @option options [Integer] :reserved
      # @option options [Integer] :flags
      # @option options [Integer] :window
      # @option options [Integer] :sum
      # @option options [Integer] :urg_pointer
      # @option options [String] :body
      def initialize(options={})
        super Int16.new(options[:sport]),
              Int16.new(options[:dport]),
              Int32.new(options[:seqnum] || rand(2**32)),
              Int32.new(options[:acknum]),
              options[:data_offset] || options[:hlen] || 5,
              options[:reserved] || 0,
              options[:flags] || 0,
              Int16.new(options[:window] || options[:wsize]),
              Int16.new(options[:sum]),
              Int16.new(options[:urg_pointer]),
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
        self[:seqnum].read str[4, 4]
        self[:acknum].read str[8, 4]
        u16 = str[12, 2].unpack('n').first
        self[:data_offset] = u16 >> 12
        self[:reserved] =  (u16 >> 9) & 0x7
        self[:flags] = u16 & 0x1ff
        self[:window].read str[14, 2]
        self[:sum].read str[16, 2]
        self[:urg_pointer].read str[18, 2]
        self[:options].read str[20, (self[:data_offset] - 5) * 4] if self[:data_offset] > 5
        self[:body].read str[self[:data_offset] * 4..-1]
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

      # Compute header length and set +data_offset+ field
      # @return [Integer]
      def calc_length
        self[:data_offset] = 5 + self[:options].sz / 4
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

      # Getter for seqnum attribuute
      # @return [Integer]
      def seqnum
        self[:seqnum].to_i
      end
      alias :sequence_number :seqnum

      # Setter for seqnum attribuute
      # @param [Integer] seq
      # @return [Integer]
      def seqnum=(seq)
        self[:seqnum].read seq
      end
      alias :sequence_number= :seqnum=

      # Getter for acknum attribuute
      # @return [Integer]
      def acknum
        self[:acknum].to_i
      end
      alias :acknowledgment_number :acknum

      # Setter for acknum attribuute
      # @param [Integer] ack
      # @return [Integer]
      def acknum=(ack)
        self[:acknum].read ack
      end
      alias :acknowledgment_number= :acknum=

      alias :hlen :data_offset
      alias :hlen= :data_offset=

      # Getter for window attribuute
      # @return [Integer]
      def window
        self[:window].to_i
      end
      alias :wsize :window

      # Setter for window attribuute
      # @param [Integer] window
      # @return [Integer]
      def window=(window)
        self[:window].read window
      end
      alias :wsize= :window=

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

      # Getter for urg_pointer attribuute
      # @return [Integer]
      def urg_pointer
        self[:urg_pointer].to_i
      end

      # Setter for urg_pointer attribuute
      # @param [Integer] urg
      # @return [Integer]
      def urg_pointer=(urg)
        self[:urg_pointer].read urg
      end

      # Get binary string
      # @return [String]
      def to_s
        ary1 = to_a[0..3]
        ary2 = to_a[7..10]
        u16 = ((self[:data_offset] & 0xf) << 12) |
              ((self[:reserved] & 0x7) << 9) |
              (self[:flags] & 0x1ff)
        ary1.map(&:to_s).join << [u16].pack('n') << ary2.map(&:to_s).join
      end
    end

    IP.bind_header TCP, protocol: TCP::IP_PROTOCOL
    IPv6.bind_header TCP, next: TCP::IP_PROTOCOL
  end
end

require_relative 'tcp/options'
