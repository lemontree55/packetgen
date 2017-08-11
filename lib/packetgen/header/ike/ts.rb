# coding: utf-8
require 'net-proto'

module PacketGen
  module Header
    class IKE

      # TrafficSelector substructure, as defined in RFC 7296, §3.13.1:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |   TS Type     |IP Protocol ID*|       Selector Length         |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |           Start Port*         |           End Port*           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                         Starting Address*                     ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                         Ending Address*                       ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class TrafficSelector < Types::Fields
        # IPv4 traffic selector type
        TS_IPV4_ADDR_RANGE = 7
        # IPv6 traffic selector type
        TS_IPV6_ADDR_RANGE = 8

        # @!attribute [r] type
        #  8-bit TS type
        #  @return [Integer]
        define_field :type, Types::Int8, default: 7
        # @!attribute [r] protocol
        #  8-bit protocol ID
        #  @return [Integer]
        define_field :protocol, Types::Int8, default: 0
        # @!attribute length
        #  16-bit Selector Length
        #  @return [Integer]
        define_field :length, Types::Int16
        # @!attribute start_port
        #  16-bit Start port
        #  @return [Integer]
        define_field :start_port, Types::Int16, default: 0
        # @!attribute end_port
        #  16-bit End port
        #  @return [Integer]
        define_field :end_port, Types::Int16, default: 65535
        # @!attribute start_addr
        #  starting address
        #  @return [IP::Addr, IPv6::Addr]
        define_field :start_addr, IP::Addr
        # @!attribute end_addr
        #  starting address
        #  @return [IP::Addr, IPv6::Addr]
        define_field :end_addr, IP::Addr

        # @param [Hash] options
        # @option [Range] :ports port range
        # @option [Integer] :start_port start port
        # @option [Integer] :end_port end port
        def initialize(options={})
          super
          select_addr options
          self[:start_addr].from_human(options[:start_addr]) if options[:start_addr]
          self[:end_addr].from_human(options[:end_addr]) if options[:end_addr]
          self[:length].value = sz unless options[:length]
          self.type = options[:type] if options[:type]
          self.protocol = options[:protocol] if options[:protocol]
          if options[:ports]
            self.start_port = options[:ports].begin
            self.end_port = options[:ports].end
          end
        end

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          super
          select_addr_from_type type
          super
        end

        # Set type
        # @param [Integer,String] value
        # @return [Integer]
        def type=(value)
          type = case value
               when Integer
                 value
               else
                 c = self.class.constants.grep(/TS_#{value.upcase}/).first
                 c ? self.class.const_get(c) : nil
               end
          raise ArgumentError, "unknown type #{value.inspect}" unless type
          select_addr_from_type type
          self[:type].value = type
        end

        # Set protocol
        # @param [Integer,String] value
        # @return [Integer]
        def protocol=(value)
          protocol = case value
               when Integer
                 value
               else
                 Net::Proto.getprotobyname(value)
               end
          raise ArgumentError, "unknown protocol #{value.inspect}" unless protocol
          self[:protocol].value = protocol
        end

        # Get a human readable string
        # @return [String]
        def to_human
          h = start_addr << '-' << end_addr
          unless human_protocol.empty?
            h << "/#{human_protocol}"
            h << "[#{start_port}-#{end_port}]" if (start_port..end_port) != (0..65535)
          end
          h
        end

        # Get human readable protocol name. If protocol ID is 0, an empty string
        # is returned.
        # @return [String]
        def human_protocol
          if protocol == 0
            ''
          else
            Net::Proto.getprotobynumber(protocol) || "#{protocol}"
          end
        end

        # Get human readable TS type
        # @return [String]
        def human_type
          case type
          when TS_IPV4_ADDR_RANGE
            'IPv4'
          when TS_IPV6_ADDR_RANGE
            'IPv6'
          else
            "type #{type}"
          end
        end

        private

        def select_addr_from_type(type)
          case type
          when TS_IPV4_ADDR_RANGE, 'IPV4', 'IPv4', 'ipv4', nil
            self[:start_addr] = IP::Addr.new unless self[:start_addr].is_a?(IP::Addr)
            self[:end_addr] = IP::Addr.new unless self[:end_addr].is_a?(IP::Addr)
          when TS_IPV6_ADDR_RANGE, 'IPV6', 'IPv6', 'ipv6'
            self[:start_addr] = IPv6::Addr.new unless self[:start_addr].is_a?(IPv6::Addr)
            self[:end_addr] = IPv6::Addr.new unless self[:end_addr].is_a?(IPv6::Addr)
          else
            raise ArgumentError, "unknown type #{type}"
          end
        end

        def select_addr(options)
          if options[:type]
            select_addr_from_type options[:type]
          elsif options[:start_addr]
            ipv4 = IPAddr.new(options[:start_addr]).ipv4?
            self.type = ipv4 ? TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE
          elsif options[:end_addr]
            ipv4 = IPAddr.new(options[:end_addr]).ipv4?
            self.type = ipv4 ? TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE
          end
        end
      end

      # Set of {TrafficSelector}, used by {TSi} and {TSr}.
      # @author Sylvain Daubert
      class TrafficSelectors < Types::Array
        set_of TrafficSelector
      end

      # This class handles Traffic Selector - Initiator payloads, denoted TSi.
      #
      # A TSi payload consists of the IKE generic payload header (see {Payload})
      # and some specific fields:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Number of TSs |                 RESERVED                      |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                       <Traffic Selectors>                     ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # These specific fields are:
      # * {#num_ts},
      # * {#reserved},
      # * and {#traffic_selectors}.
      #
      # == Create a TSi payload
      #  # Create a IKE packet with a TSi payload
      #  pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::TSi')
      #  # add a traffic selector to this payload
      #  pkt.ike_tsi.traffic_selectors << { protocol: 'tcp', ports: 1..1024, start_addr: '20.0.0.1', end_addr: '21.255.255.254' }
      #  # add another traffic selector (IPv6, all protocols)
      #  pkt.ike_tsi.traffic_selectors << { start_addr: '2001::1', end_addr: '200a:ffff:ffff:ffff:ffff:ffff:ffff:ffff' }
      # @author Sylvain Daubert
      class TSi < Payload

        # Payload type number
        PAYLOAD_TYPE = 44

        delete_field :content
        # @!attribute num_ts
        #   8-bit Number of TSs
        #   @return [Integer]
        define_field_before :body, :num_ts, Types::Int8
        # @!attribute rsv1
        #   First 8-bit RESERVED field
        #   @return [Integer]
        define_field_before :body, :rsv1, Types::Int8
        # @!attribute rsv1
        #   Last 16-bit RESERVED field
        #   @return [Integer]
        define_field_before :body, :rsv2, Types::Int16

        # @!attribute traffic_selectors
        #  Set of {TrafficSelector}
        #  @return {TrafficSelectors}
        define_field_before :body, :traffic_selectors, TrafficSelectors,
                            builder: ->(ts) { TrafficSelectors.new(counter: ts[:num_ts]) }
        alias :selectors :traffic_selectors

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          super(str[0, 8])
          hlen = self.class.new.sz
          tslen = length - hlen
          selectors.read str[hlen, tslen]
          body.read str[hlen+tslen..-1]
          self
        end

        # Compute length and set {#length} field
        # @return [Integer] new length
        def calc_length
          selectors.each { |p| p.calc_length }
          super
        end

        # @return [String]
        def inspect
          str = Inspect.dashed_line(self.class, 2)
          fields.each do |attr|
            case attr
            when :body, :rsv2
              next
            when :rsv1
              str << Inspect.shift_level(2)
              str << Inspect::FMT_ATTR % ['Int24', 'reserved',
                                          (rsv1 << 16) | rsv2 ]
            else
              str << Inspect.inspect_attribute(attr, self[attr], 2)
            end
          end
          str
        end
     end

      class TSr < TSi
        # Payload type number
        PAYLOAD_TYPE = 45
      end
    end

    self.add_class IKE::TSi
    self.add_class IKE::TSr
  end
end
