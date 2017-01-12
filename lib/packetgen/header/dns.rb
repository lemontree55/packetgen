module PacketGen
  module Header

    # DNS: Domain Name Service
    #
    # A DNS packet consists of a header:
    #                                  1  1  1  1  1  1
    #    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                      ID                       |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                    QDCOUNT                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                    ANCOUNT                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                    NSCOUNT                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                    ARCOUNT                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # A DNS packet also contains up to 4 sections:
    # * {#qd}, question section,
    # * {#an}, answer section,
    # * {#ns}, authoritary section,
    # * {#ar}, additional information section.
    # @author Sylvain Daubert
    class DNS < Struct.new(:id, :u16, :qdcount, :ancount, :nscount, :arcount,
                           :qd, :an, :ns, :ar)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods
    end
  end
end

require_relative 'dns/rrsection'
require_relative 'dns/qdsection'
require_relative 'dns/labels'
require_relative 'dns/base_rr'
require_relative 'dns/rr'
require_relative 'dns/question'

module PacketGen
  module Header
    class DNS
      # Port number for DNS over UDP
      UDP_PORT = 53
      # Port number for DNS over TCP
      TCP_PORT = UDP_PORT

      # DNS opcodes
      OPCODES = {
        'query'  => 0,
        'iquery' => 1,
        'status' => 2,
        'notify' => 4,
        'update' => 5
      }

      # DNS Response codes
      RCODES = {
        'ok'              => 0,
        'no-error'        => 0,
        'format-error'    => 1,
        'server-failure'  => 2,
        'name-error'      => 3,
        'not-implemented' => 4,
        'refused'         => 5
      }

      # @private onlu useful for define_bit_fields_on
      def initialize(options={})
        super Int16.new(options[:id]),
              Int16.new,
              Int16.new(options[:qdcount]),
              Int16.new(options[:ancount]),
              Int16.new(options[:nscount]),
              Int16.new(options[:arcount])
        
        self[:qd] = QDSection.new(self, self[:qdcount])
        self[:an] = RRSection.new(self, self[:ancount])
        self[:ns] = RRSection.new(self, self[:nscount])
        self[:ar] = RRSection.new(self, self[:arcount])
      end
      alias old_initialize initialize

      # @!attribute qr
      #   @return [Boolean] query (+false+) or response (+true+)
      # @!attribute opcode
      #   @return [Integer] Kind of query. See {OPCODES}.
      # @!attribute aa
      #   @return [Boolean] Authoritative answer
      # @!attribute tc
      #   @return [Boolean] Truncation
      # @!attribute rd
      #   @return [Boolean] Recursion Desired
      # @!attribute ra
      #   @return [Boolean] Recursion Available
      # @!attribute ad
      #   @return [Boolean] Authentic Data
      # @!attribute cd
      #   @return [Boolean] Checking Disabled
      # @!attribute rcode
      #   @return [Integer] Response code. See {RCODES}.
      define_bit_fields_on :u16, :qr, :opcode, 4, :aa, :tc, :rd, :ra, :z,
                           :ad, :cd, :rcode, 4

      # @param [Hash] options
      # @option options [Integer] :id
      # @option options [Integer] :qdcount
      # @option options [Integer] :ancount
      # @option options [Integer] :nscount
      # @option options [Integer] :arcount
      # @option optons [Boolean] :qr
      # @option optons [Integer,String] :opcode
      # @option optons [Boolean] :aa
      # @option optons [Boolean] :tc
      # @option optons [Boolean] :rd
      # @option optons [Boolean] :ra
      # @option optons [Integer,String] :rcode
      def initialize(options={})
        old_initialize(options)

        qr = boolean2integer(options[:qr])
        aa = boolean2integer(options[:aa])
        tc = boolean2integer(options[:tc])
        rd = boolean2integer(options[:rd])
        ra = boolean2integer(options[:ra])
        self.u16.read (qr << 15) | (aa << 10) | (tc << 9) | (rd << 8) | (ra << 7)
        self.opcode = options[:opcode] || OPCODES['query']
        self.rcode = options[:rcode] || RCODES['ok']
      end

      # Read DNS header and sections from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        return self if str.nil?
        force_binary str
        self[:id].read str[0, 2]
        self[:u16].read str[2, 2]
        self[:qdcount].read str[4, 2]
        self[:ancount].read str[6, 2]
        self[:nscount].read str[8, 2]
        self[:arcount].read str[10, 2]
        self[:qd].read str[12..-1] if self.qdcount > 0
        start = 12 + self.qd.sz
        self[:an].read str[start..-1] if self.ancount > 0
        start += self.an.sz
        self[:ns].read str[start..-1] if self.nscount > 0
        start += self.ns.sz
        self[:ar].read str[start..-1] if self.arcount > 0
        self
      end

      # Getter for id
      # @return [Integer]
      def id
        self[:id].to_i
      end

      # Setter for id
      # @param [Integer] id
      # @return [Integer]
      def id=(id)
        self[:id].read id
      end

      # Getter for qdcount
      # @return [Integer]
      def qdcount
        self[:qdcount].to_i
      end

      # Setter for qdcount
      # @param [Integer] qdcount
      # @return [Integer]
      def qdcount=(qdcount)
        self[:qdcount].read qdcount
      end

      # Getter for ancount
      # @return [Integer]
      def ancount
        self[:ancount].to_i
      end

      # Setter for ancount
      # @param [Integer] ancount
      # @return [Integer]
      def ancount=(ancount)
        self[:ancount].read ancount
      end

      # Getter for nscount
      # @return [Integer]
      def nscount
        self[:nscount].to_i
      end

      # Setter for nscount
      # @param [Integer] nscount
      # @return [Integer]
      def nscount=(nscount)
        self[:nscount].read nscount
      end

      # Getter for arcount
      # @return [Integer]
      def arcount
        self[:arcount].to_i
      end

      # Setter for arcount
      # @param [Integer] arcount
      # @return [Integer]
      def arcount=(arcount)
        self[:arcount].read arcount
      end

      alias old_opcode= opcode=
      # Set opcode
      # @param [Integer,String] value
      # @return [Integer]
      def opcode=(value)
        intg = case value
               when Integer
                 value
               else
                 OPCODES[value.to_s]
               end
        raise ArgumentError, "unknwon opcode #{value.inspect}" unless intg
        self.old_opcode = intg
      end

      alias old_rcode= rcode=
      # Set rcode
      # @param [Integer,String] value
      # @return [Integer]
      def rcode=(value)
        intg = case value
               when Integer
                 value
               else
                 RCODES[value]
               end
        raise ArgumentError, "unknwon rcode #{value.inspect}" unless intg
        self.old_rcode = intg
      end

      # Is message a response
      # @return [Boolean]
      def response?
        qr?
      end

      # Is message a query
      # @return [Boolean]
      def query?
        !qr?
      end

      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        to_h.each do |attr, value|
          if attr == :u16
            flags = [:qr, :aa, :tc, :rd, :ra].select! { |attr| send "#{attr}?" }.
                    map(&:to_s).join(',')
            str << Inspect.shift_level(2)
            str << Inspect::INSPECT_FMT_ATTR % ['Flags', 'flags', flags]
            opcode = '%-10s (%u)' % [OPCODES.key(self.opcode), self.opcode]
            str << Inspect.shift_level(2)
            str << Inspect::INSPECT_FMT_ATTR % ['Integer', 'opcode', opcode]
            rcode = '%-10s (%u)' % [RCODES.key(self.rcode), self.rcode]
            str << Inspect.shift_level(2)
            str << Inspect::INSPECT_FMT_ATTR % ['Integer', 'rcode', rcode]
          else
            str << Inspect.inspect_attribute(attr, value, 2)
          end
        end
        str
      end

      private

      def boolean2integer(bool)
        bool ? 1 : 0
      end
    end

    self.add_class DNS
    UDP.bind_header DNS, dport: DNS::UDP_PORT, sport: DNS::UDP_PORT
    TCP.bind_header DNS, dport: DNS::TCP_PORT, sport: DNS::TCP_PORT
  end
end
