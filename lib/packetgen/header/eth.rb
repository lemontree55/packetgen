# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # An Ethernet header consists of:
    # * a destination MAC address ({MacAddr}),
    # * a source MAC address (MacAddr),
    # * a {#ethertype} ({Int16}),
    # * and a body (a {String} or another Header class).
    #
    # == Create a Ethernet header
    #  # standalone
    #  eth = PacketGen::Header::Eth.new
    #  # in a packet
    #  pkt = PacketGen.gen('Eth')
    #  # access to Ethernet header
    #  pkt.eth   # => PacketGen::Header::Eth
    #
    # == Ethernet attributes
    #  eth.dst = "00:01:02:03:04:05'
    #  eth.src        # => "00:01:01:01:01:01"
    #  eth[:src]      # => PacketGen::Header::Eth::MacAddr
    #  eth.ethertype  # => 16-bit Integer
    #  eth.body = "This is a body"
    #
    # @author Sylvain Daubert
    class Eth < Struct.new(:dst, :src, :ethertype, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # Ethernet MAC address, as a group of 6 bytes
      # @author Sylvain Daubert
      class MacAddr < Struct.new(:a0, :a1, :a2, :a3, :a4, :a5)
        include StructFu
        
        # @param [Hash] options
        # @option options [Integer] :a0
        # @option options [Integer] :a1
        # @option options [Integer] :a2
        # @option options [Integer] :a3
        # @option options [Integer] :a4
        # @option options [Integer] :a5
        def initialize(options={})
          super Int8.new(options[:a0]),
                Int8.new(options[:a1]),
                Int8.new(options[:a2]),
                Int8.new(options[:a3]),
                Int8.new(options[:a4]),
                Int8.new(options[:a5])

        end

        # Parse a string to populate +MacAddr+
        # @param [String] str
        # @return [self]
        def parse(str)
          return self if str.nil?
          bytes = str.split(/:/)
          unless bytes.size == 6
            raise ArgumentError, 'not a MAC address'
          end
          self[:a0].read(bytes[0].to_i(16))
          self[:a1].read(bytes[1].to_i(16))
          self[:a2].read(bytes[2].to_i(16))
          self[:a3].read(bytes[3].to_i(16))
          self[:a4].read(bytes[4].to_i(16))
          self[:a5].read(bytes[5].to_i(16))
          self
        end

        # Read a +MacAddr+ from a binary string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          return self if str.nil?
          raise ParseError, 'string too short for Eth' if str.size < self.sz
          force_binary str
          [:a0, :a1, :a2, :a3, :a4, :a5].each_with_index do |byte, i|
            self[byte].read str[i, 1]
          end
        end

        [:a0, :a1, :a2, :a3, :a4, :a5].each do |sym|
          class_eval "def #{sym}; self[:#{sym}].to_i; end\n" \
                     "def #{sym}=(v); self[:#{sym}].read v; end"
        end

        # +MacAddr+ in human readable form (colon format)
        # @return [String]
        def to_x
          members.map { |m| "#{'%02x' % self[m]}" }.join(':')
        end
      end

      # @private snap length for PCAPRUB
      PCAP_SNAPLEN = 0xffff
      # @private promiscuous (or not) for PCAPRUB
      PCAP_PROMISC = false
      # @private timeout for PCAPRUB
      PCAP_TIMEOUT = 1

      # @param [Hash] options
      # @option options [String] :dst MAC destination address
      # @option options [String] :src MAC source address
      # @option options [Integer] :ethertype
      def initialize(options={})
        super MacAddr.new.parse(options[:dst] || '00:00:00:00:00:00'),
              MacAddr.new.parse(options[:src] || '00:00:00:00:00:00'),
              Int16.new(options[:ethertype] || 0),
              StructFu::String.new.read(options[:body])
      end

      # Read a Eth header from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        return self if str.nil?
        raise ParseError, 'string too short for Eth' if str.size < self.sz
        force_binary str
        self[:dst].read str[0, 6]
        self[:src].read str[6, 6]
        self[:ethertype].read str[12, 2]
        self[:body].read str[14..-1]
        self
      end

      # Get MAC destination address
      # @return [String]
      def dst
        self[:dst].to_x
      end

      # Set MAC destination address
      # @param [String] addr
      # @return [String]
      def dst=(addr)
        self[:dst].parse addr
      end

      # Get MAC source address
      # @return [String]
      def src
        self[:src].to_x
      end

      # Set MAC source address
      # @param [String] addr
      # @return [String]
      def src=(addr)
        self[:src].parse addr
      end

      # Get ethertype field
      # @return [Integer]
      def ethertype
        self[:ethertype].to_i
      end

      # Set ethertype field
      # @param [Integer] type
      # @return [Integer]
      def ethertype=(type)
        self[:ethertype].value = type
      end

      # send Eth packet on wire.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface)
        pcap = PCAPRUB::Pcap.open_live(iface, PCAP_SNAPLEN, PCAP_PROMISC, PCAP_TIMEOUT)
        pcap.inject self.to_s
      end
    end
  end
end
