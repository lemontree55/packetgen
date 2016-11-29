module PacketGen
  module Header

    # ARP header class
    # @author Sylvain Daubert
    class ARP < Struct.new(:hw_type, :proto, :hw_len, :proto_len, :opcode,
                          :src_mac, :src_ip, :dst_mac, :dst_ip, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # @param [Hash] options
      # @option options [Integer] :hw_type network protocol type (default: 1)
      # @option options [Integer] :proto internet protocol type (default: 0x800)
      # @option options [Integer] :hw_len length of hardware addresses (default: 6)
      # @option options [Integer] :proto_len length of internet addresses (default: 4)
      # @option options [Integer] :opcode operation performing by sender (default: 1).
      #   known values are +request+ (1) and +reply+ (2)
      # @option options [String] :src_mac sender hardware address
      # @option options [String] :src_ip sender internet address
      # @option options [String] :dst_mac target hardware address
      # @option options [String] :dst_ip targetr internet address
       def initialize(options={})
        super Int16.new(options[:hw_type] || 1),
              Int16.new(options[:proto] || 0x800),
              Int8.new(options[:hw_len] || 6),
              Int8.new(options[:proto_len] || 4),
              Int16.new(options[:opcode] || 1),
              Eth::MacAddr.new.parse(options[:src_mac]),
              IP::Addr.new.parse(options[:src_ip]),
              Eth::MacAddr.new.parse(options[:dst_mac]),
              IP::Addr.new.parse(options[:dst_ip]),
              StructFu::String.new.read(options[:body])
      end

      # Read a ARP header from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        force_binary str
        raise ParseError, 'string too short for ARP' if str.size < self.sz
        self[:hw_type].read str[0, 2]
        self[:proto].read str[2, 2]
        self[:hw_len].read str[4, 1]
        self[:proto_len].read str[5, 1]
        self[:opcode].read str[6, 2]
        self[:src_mac].read str[8, 6]
        self[:src_ip].read str[14, 4]
        self[:dst_mac].read str[18, 6]
        self[:dst_ip].read str[24, 4]
        self[:body].read str[28..-1]
      end

      # @!attribute [rw] hw_type
      # @return [Integer]
      def hw_type
        self[:hw_type].to_i
      end
      
      def hw_type=(i)
        self[:hw_type].read i
      end

      # @!attribute [rw] proto
      # @return [Integer]
      def proto
        self[:proto].to_i
      end
      
      def proto=(i)
        self[:proto].read i
      end

      # @!attribute [rw] hw_len
      # @return [Integer]
      def hw_len
        self[:hw_len].to_i
      end
      
      def hw_len=(i)
        self[:hw_len].read i
      end

      # @!attribute [rw] proto_len
      # @return [Integer]
      def proto_len
        self[:proto_len].to_i
      end
      
      def proto_len=(i)
        self[:proto_len].read i
      end

      # @!attribute [rw] opcode
      # @return [Integer]
      def opcode
        self[:opcode].to_i
      end
      
      def opcode=(i)
        self[:opcode].read i
      end

      # @!attribute [rw] src_mac
      # @return [String]
      def src_mac
        self[:src_mac].to_x
      end
      
      def src_mac=(addr)
        self[:src_mac].parse addr
      end

      # @!attribute [rw] src_ip
      # @return [String]
      def src_ip
        self[:src_ip].to_x
      end
      
      def src_ip=(addr)
        self[:src_ip].parse addr
      end

      # @!attribute [rw] dst_mac
      # @return [String]
      def dst_mac
        self[:dst_mac].to_x
      end
      
      def dst_mac=(addr)
        self[:dst_mac].parse addr
      end

      # @!attribute [rw] dst_ip
      # @return [String]
      def dst_ip
        self[:dst_ip].to_x
      end
      
      def dst_ip=(addr)
        self[:dst_ip].parse addr
      end
    end

    Eth.bind_header ARP, proto: 0x806
  end
end

