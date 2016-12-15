module PacketGen
  module Header

    # ARP header class
    # @author Sylvain Daubert
    class ARP < Struct.new(:hrd, :pro, :hln, :pln, :op,
                           :sha, :spa, :tha, :tpa, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # @param [Hash] options
      # @option options [Integer] :hrd network protocol type (default: 1)
      # @option options [Integer] :pro internet protocol type (default: 0x800)
      # @option options [Integer] :hln length of hardware addresses (default: 6)
      # @option options [Integer] :pln length of internet addresses (default: 4)
      # @option options [Integer] :op operation performing by sender (default: 1).
      #   known values are +request+ (1) and +reply+ (2)
      # @option options [String] :sha sender hardware address
      # @option options [String] :spa sender internet address
      # @option options [String] :tha target hardware address
      # @option options [String] :tpa targetr internet address
       def initialize(options={})
        super Int16.new(options[:hrd] || options[:htype] || 1),
              Int16.new(options[:pro] || options[:ptype] || 0x800),
              Int8.new(options[:hln] || options[:hlen] || 6),
              Int8.new(options[:pln] || options[:plen] || 4),
              Int16.new(options[:op] || options[:opcode] || 1),
              Eth::MacAddr.new.parse(options[:sha] || options[:src_mac]),
              IP::Addr.new.parse(options[:spa] || options[:src_ip]),
              Eth::MacAddr.new.parse(options[:tha] || options[:dst_mac]),
              IP::Addr.new.parse(options[:tpa] || options[:dst_ip]),
              StructFu::String.new.read(options[:body])
      end

      # Read a ARP header from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        force_binary str
        raise ParseError, 'string too short for ARP' if str.size < self.sz
        self[:hrd].read str[0, 2]
        self[:pro].read str[2, 2]
        self[:hln].read str[4, 1]
        self[:pln].read str[5, 1]
        self[:op].read str[6, 2]
        self[:sha].read str[8, 6]
        self[:spa].read str[14, 4]
        self[:tha].read str[18, 6]
        self[:tpa].read str[24, 4]
        self[:body].read str[28..-1]
      end

      # @!attribute [rw] hrd
      # @return [Integer]
      def hrd
        self[:hrd].to_i
      end
      alias :htype :hrd
      
      def hrd=(i)
        self[:hrd].read i
      end
      alias :htype= :hrd=

      # @!attribute [rw] pro
      # @return [Integer]
      def pro
        self[:pro].to_i
      end
      alias :ptype :pro
      
      def pro=(i)
        self[:pro].read i
      end
      alias :ptype= :pro=

      # @!attribute [rw] hln
      # @return [Integer]
      def hln
        self[:hln].to_i
      end
      alias :hlen :hln
      
      def hln=(i)
        self[:hln].read i
      end
      alias :hlen= :hln=

      # @!attribute [rw] pln
      # @return [Integer]
      def pln
        self[:pln].to_i
      end
      alias :plen :pln
      
      def pln=(i)
        self[:pln].read i
      end
      alias :plen= :pln=

      # @!attribute [rw] op
      # @return [Integer]
      def op
        self[:op].to_i
      end
      alias :opcode :op
      
      def op=(i)
        self[:op].read i
      end
      alias :opcode= :op=

      # @!attribute [rw] sha
      # @return [String]
      def sha
        self[:sha].to_x
      end
      alias :src_mac :sha
      
      def sha=(addr)
        self[:sha].parse addr
      end
      alias :src_mac= :sha=

      # @!attribute [rw] spa
      # @return [String]
      def spa
        self[:spa].to_x
      end
      alias :src_ip :spa
      
      def spa=(addr)
        self[:spa].parse addr
      end
      alias :src_ip= :spa=

      # @!attribute [rw] tha
      # @return [String]
      def tha
        self[:tha].to_x
      end
      alias :dst_mac :tha
      
      def tha=(addr)
        self[:tha].parse addr
      end
      alias :dst_mac= :tha=

      # @!attribute [rw] tpa
      # @return [String]
      def tpa
        self[:tpa].to_x
      end
      alias :dst_ip :tpa
      
      def tpa=(addr)
        self[:tpa].parse addr
      end
      alias :dst_ip= :tpa=
    end

    Eth.bind_header ARP, ethertype: 0x806
  end
end

