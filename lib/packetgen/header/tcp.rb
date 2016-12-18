module PacketGen
  module Header

    # A TCP header consists of:
    # * a source port ({#sport}, {Int16} type),
    # * a destination port ({#dport}, +Int16+ type),
    # * a sequence number ({#seqnum}, {Int32} type),
    # * an acknownledge number ({#acknum}, +Int32+ type),
    # * a 16-bit field ({#u16}, +Int16+ type) composed of:
    #   * a 4-bit {#data_offset} value,
    #   * a 3-bit {#reserved} field,
    #   * a 9-bit {#flags} field,
    # * a {#window} field (+Int16+ type),
    # * a {#checksum} field (+Int16+ type),
    # * a urgent pointer ({#urg_pointer}, +Int16+ type),
    # * an optional {#options} field ({Options} type),
    # * and a {#body} ({String} type).
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
    #  tcph.seqnum = 43
    #  tcph.acknum = 0x45678925
    #  tcph.wsize = 0x240
    #  tcph.urg_pointer = 0x40
    #  tcph.body.read 'this is a body'
    #
    # == Flags
    # TCP flags may be accesed as a 9-bit integer:
    #  tcph.flags = 0x1002
    # Each flag may be accessed independently:
    #  tcph.flag_syn?    # => Boolean
    #  tcph.flag_rst = true
    #
    # == Options
    # {#options} TCP attribute is a {Options}. {Option} may added to it:
    #  tcph.options << PacketGen::Header::TCP::MSS.new(1250)
    # Another way is to use {Options#add}:
    #  tcph.options.add 'MSS', 1250
    # @author Sylvain Daubert
    class TCP < Struct.new(:sport, :dport, :seqnum, :acknum, :u16,
                           :window, :checksum, :urg_pointer, :options, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods
    end
  end
end

# Need to load Options now, as this is used through define_bit_fields_on,
# which make a call to TCP.new, which needs Options
require_relative 'tcp/options'

module PacketGen
  module Header
    class TCP
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
      # @option options [Integer] :checksum
      # @option options [Integer] :urg_pointer
      # @option options [String] :body
      def initialize(options={})
        super Int16.new(options[:sport]),
              Int16.new(options[:dport]),
              Int32.new(options[:seqnum] || rand(2**32)),
              Int32.new(options[:acknum]),
              Int16.new,
              Int16.new(options[:window] || options[:wsize]),
              Int16.new(options[:checksum]),
              Int16.new(options[:urg_pointer]),
              Options.new,
              StructFu::String.new.read(options[:body])

        doff = options[:data_offset] || options[:hlen] || 5
        rsv = options[:reserved] || 0
        flgs = options[:flags] || 0
        self.u16.read (((doff << 3) | rsv) << 9) | flgs
      end

      # @!attribute data_offset
      #  @return [Integer] 4-bit data offsetfrom {#u16}
      # @!attribute reserved
      #  @return [Integer] 3-bit reserved from {#u16}
      # @!attribute flags
      #  @return [Integer] 9-bit flags from {#u16}
      define_bit_fields_on :u16, :data_offset, 4, :reserved, 3, :flags, 9
      alias :hlen :data_offset
      alias :hlen= :data_offset=

      # @!attribute flag_ns
      #  @return [Boolean] 1-bit NS flag
      # @!attribute flag_cwr
      #  @return [Boolean] 1-bit CWR flag
      # @!attribute flag_ece
      #  @return [Boolean] 1-bit ECE flag
      # @!attribute flag_urg
      #  @return [Boolean] 1-bit URG flag
      # @!attribute flag_ack
      #  @return [Boolean] 1-bit ACK flag
      # @!attribute flag_psh
      #  @return [Boolean] 1-bit PSH flag
      # @!attribute flag_rst
      #  @return [Boolean] 1-bit RST flag
      # @!attribute flag_syn
      #  @return [Boolean] 1-bit SYN flag
      # @!attribute flag_fin
      #  @return [Boolean] 1-bit FIN flag
      define_bit_fields_on :u16, :_, 7, :flag_ns, :flag_cwr, :flag_ece, :flag_urg,
                           :flag_ack, :flag_psh, :flag_rst, :flag_syn, :flag_fin
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
        self[:u16].read str[12, 2]
        self[:window].read str[14, 2]
        self[:checksum].read str[16, 2]
        self[:urg_pointer].read str[18, 2]
        self[:options].read str[20, (self.data_offset - 5) * 4] if self.data_offset > 5
        self[:body].read str[self.data_offset * 4..-1]
      end

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = ip_header(self).pseudo_header_checksum
        sum += IP_PROTOCOL
        sum += self.sz
        str = self.to_s
        str << "\x00" if str.length % 2 == 1
        sum += str.unpack('n*').reduce(:+)

        while sum > 0xffff do
          sum = (sum & 0xffff) + (sum >> 16)
        end
        sum = ~sum & 0xffff
        self[:checksum].value = (sum == 0) ? 0xffff : sum
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

      # Getter for checksum attribuute
      # @return [Integer]
      def checksum
        self[:checksum].to_i
      end

      # Setter for checksum attribuute
      # @param [Integer] sum
      # @return [Integer]
      def checksum=(sum)
        self[:checksum].read sum
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
    end

    IP.bind_header TCP, protocol: TCP::IP_PROTOCOL
    IPv6.bind_header TCP, next: TCP::IP_PROTOCOL
  end
end
