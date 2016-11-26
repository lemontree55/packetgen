module PacketGen
  module Header

    # IP header class
    # @author Sylvain Daubert
    class IP < Struct.new(:version, :ihl, :tos, :len, :id, :frag, :ttl,
                          :proto,:sum, :src, :dst, :body)
      include StructFu
      extend HeaderClassMethods

      # IP address, as a group of 4 bytes
      # @author Sylvain Daubert
      class Addr < Struct.new(:a1, :a2, :a3, :a4)
        include StructFu

        IPV4_ADDR_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

        # Parse a dotted address
        # @param [String] str
        # @return [self]
        def parse(str)
          m = str.match(IPV4_ADDR_REGEX)
          if m
            self[:a1] = m[1].to_i
            self[:a2] = m[2].to_i
            self[:a3] = m[3].to_i
            self[:a4] = m[4].to_i
          end
          self
        end

        # Addr in human readable form (dotted format)
        # @return [String]
        def to_x
          members.map { |m| "#{self[m].to_i}" }.join('.')
        end

        # Addr as an integer
        # @return [Integer]
        def to_i
          (self.a1.to_i << 24) | (self.a2.to_i << 16) | (self.a3.to_i << 8) |
            self.a4.to_i
        end

        # Get binary string
        # @return [String]
        def to_s
          [to_i].pack('N')
        end
      end

      # @param [Hash] options
      def initialize(options={})
        super options[:version] || 4,
              options[:ihl] || 5,
              Int8.new(options[:tos] || 0),
              Int16.new(options[:len] || 20),
              Int16.new(options[:id] || rand(65535)),
              Int16.new(options[:frag] || 0),
              Int8.new(options[:ttl] || 64),
              Int8.new(options[:proto]),
              Int16.new(options[:sum] || 0),
              Addr.new.parse(options[:src] || '127.0.0.1'),
              Addr.new.parse(options[:dst] || '127.0.0.1'),
              StructFu::String.new.read(options[:body])
      end

      # Compute checksum and set +sum+ field
      # @return [Integer]
      def calc_sum
        checksum = (self.version << 12) | (self.ihl << 8) | self.tos
        checksum += self.len
        checksum += self.id
        checksum += self.frag
        checksum += (self.ttl << 8) | self.proto
        checksum += (self[:src].to_i >> 16)
        checksum += (self[:src].to_i & 0xffff)
        checksum += self[:dst].to_i >> 16
        checksum += self[:dst].to_i & 0xffff
        checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = ~(checksum % 0xffff ) & 0xffff
        self[:sum].value = (checksum == 0) ? 0xffff : checksum
      end

      # Getter for TOS attribute
      # @return [Integer]
      def tos
        self[:tos].to_i
      end

      # Setter for TOS attribute
      # @param [Integer] tos
      # @return [Integer]
      def tos=(tos)
        self[:tos].value = tos
      end

      # Getter for len attribute
      # @return [Integer]
      def len
        self[:len].to_i
      end

      # Setter for len attribute
      # @param [Integer] len
      # @return [Integer]
      def len=(len)
        self[:len].value = len
      end

      # Getter for id attribute
      # @return [Integer]
      def id
        self[:id].to_i
      end

      # Setter for id attribute
      # @param [Integer] id
      # @return [Integer]
      def id=(id)
        self[:id].value = id
      end

      # Getter for  frag attribute
      # @return [Integer]
      def frag
        self[:frag].to_i
      end

      # Setter for frag attribute
      # @param [Integer] frag
      # @return [Integer]
      def frag=(frag)
        self[:frag].value = frag
      end

      # Getter for ttl attribute
      # @return [Integer]
      def ttl
        self[:ttl].to_i
      end

      # Setter for ttl attribute
      # @param [Integer] ttl
      # @return [Integer]
      def ttl=(ttl)
        self[:ttl].value = ttl
      end

      # Getter for proto attribute
      # @return [Integer]
      def proto
        self[:proto].to_i
      end

      # Setter for  proto attribute
      # @param [Integer] proto
      # @return [Integer]
      def proto=(proto)
        self[:proto].value = proto
      end

      # Getter for sum attribute
      # @return [Integer]
      def sum
        self[:sum].to_i
      end

      # Setter for  sum attribute
      # @param [Integer] sum
      # @return [Integer]
      def sum=(sum)
        self[:sum].value = sum
      end

      # Get IP source address
      # @return [String] dotted address
      def src
        self[:src].to_x
      end
      alias :source :src

      # Set IP source address
      # @param [String] addr dotted IP address
      # @return [String]
      def src=(addr)
        self[:src].parse addr
      end
      alias :source= :src=

      # Get IP destination address
      # @return [String] dotted address
      def dst
        self[:dst].to_x
      end
      alias :destination :dst

      # Set IP destination address
      # @param [String] addr dotted IP address
      # @return [String]
      def dst=(addr)
        self[:dst].parse addr
      end
      alias :destination= :dst=

      # Get binary string
      # @return [String]
      def to_s
        first_byte = [(version << 4) | ihl].pack('C')
        first_byte << to_a[2..-2].map { |field| field.to_s }.join
      end
    end

    Eth.bind_layer IP, proto: 0x800
    IP.bind_layer IP, proto: 4
  end
end
