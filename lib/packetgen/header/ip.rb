# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'socket'

module PacketGen
  module Header

    # A IP header consists of:
    # * a first byte ({#u8} of {Int8} type) composed of:
    #   * a 4-bit {#version} field,
    #   * a 4-bit IP header length ({#ihl}) field,
    # * a total length ({#length}, {Int16} type),
    # * a ID ({#id}, +Int16+ type),
    # * a {#frag} worg (+Int16+) composed of:
    #   * 3 1-bit flags ({#flag_rsv}, {#flag_df} and {#flag_mf}),
    #   * a 13-bit {#fragment_offset} field,
    # * a Time-to-Live ({#ttl}) field (+Int8+),
    # * a {#protocol} field (+Int8+),
    # * a {#checksum} field (+Int16+),
    # * a source IP address ({#src}, {Addr} type),
    # * a destination IP ddress ({#dst}, +Addr+ type),
    # * and a {#body} ({String} type).
    #
    # == Create a IP header
    #  # standalone
    #  ip = PacketGen::Header::IP.new
    #  # in a packet
    #  pkt = PacketGen.gen('IP')
    #  # access to IP header
    #  pkt.ip   # => PacketGen::Header::IP
    #
    # == IP attributes
    #  ip.u8 = 0x45
    #  # the same as
    #  ip.version = 4
    #  ip.ihl = 5
    #
    #  ip.length = 0x43
    #  ip.id = 0x1234
    #
    #  ip.frag = 0x2031
    #  # the same as:
    #  ip.flag_mf = true
    #  ip.fragment_offset = 0x31
    #
    #  ip.flag_rsv?  # => Boolean
    #  ip.flag_df?   # => Boolean
    #  ip.flag_mf?   # => Boolean
    #
    #  ip.ttl = 0x40
    #  ip.protocol = 6
    #  ip.checksum = 0xffff
    #  ip.src = '127.0.0.1'
    #  ip.src                # => "127.0.0.1"
    #  ip[:src]              # => PacketGen::Header::IP::Addr
    #  ip.dst = '127.0.0.2'
    #  ip.body.read 'this is a body'
    # @author Sylvain Daubert
    class IP < Struct.new(:u8, :tos, :length, :id, :frag, :ttl,
                          :protocol, :checksum, :src, :dst, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # IP address, as a group of 4 bytes
      # @author Sylvain Daubert
      class Addr < Struct.new(:a1, :a2, :a3, :a4)
        include StructFu

        IPV4_ADDR_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

        # @param [Hash] options
        # @option options [Integer] :a1
        # @option options [Integer] :a2
        # @option options [Integer] :a3
        # @option options [Integer] :a4
        def initialize(options={})
          super Int8.new(options[:a1]),
                Int8.new(options[:a2]),
                Int8.new(options[:a3]),
                Int8.new(options[:a4])

        end

        # Read a dotted address
        # @param [String] str
        # @return [self]
        def from_human(str)
          return self if str.nil?
          m = str.match(IPV4_ADDR_REGEX)
          if m
            self[:a1].read m[1].to_i
            self[:a2].read m[2].to_i
            self[:a3].read m[3].to_i
            self[:a4].read m[4].to_i
          end
          self
        end

        # Read a Addr from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          return self if str.nil?
          raise ParseError, 'string too short for IP::Addr' if str.size < self.sz
          force_binary str
          [:a1, :a2, :a3, :a4].each_with_index do |byte, i|
            self[byte].read str[i, 1]
          end
        end

        [:a1, :a2, :a3, :a4].each do |sym|
          class_eval "def #{sym}; self[:#{sym}].to_i; end\n" \
                     "def #{sym}=(v); self[:#{sym}].read v; end" 
        end

        # Addr in human readable form (dotted format)
        # @return [String]
        def to_human
          members.map { |m| "#{self[m].to_i}" }.join('.')
        end

        # Addr as an integer
        # @return [Integer]
        def to_i
          (self.a1 << 24) | (self.a2 << 16) | (self.a3 << 8) |
            self.a4
        end
      end

      # @param [Hash] options
      # @option options [Integer] :version
      # @option options [Integer] :ihl this header size in 4-byte words
      # @option options [Integer] :tos
      # @option options [Integer] :length IP packet length, including this header
      # @option options [Integer] :id
      # @option options [Integer] :frag
      # @option options [Integer] :ttl
      # @option options [Integer] :protocol
      # @option options [Integer] :checksum IP header checksum
      # @option options [String] :src IP source dotted address
      # @option options [String] :dst IP destination dotted address
      def initialize(options={})
        super Int8.new(((options[:version] || 4) << 4) | (options[:ihl] || 5)),
              Int8.new(options[:tos] || 0),
              Int16.new(options[:length] || 20),
              Int16.new(options[:id] || rand(65535)),
              Int16.new(options[:frag] || 0),
              Int8.new(options[:ttl] || 64),
              Int8.new(options[:protocol]),
              Int16.new(options[:checksum] || 0),
              Addr.new.from_human(options[:src] || '127.0.0.1'),
              Addr.new.from_human(options[:dst] || '127.0.0.1'),
              StructFu::String.new.read(options[:body])
      end

      # @!attribute version
      #   @return [Integer] 4-bit version attribute
      # @!attribute ihl
      #   @return [Integer] 4-bit IP header length attribute
      define_bit_fields_on :u8, :version, 4, :ihl, 4

      # @!attribute flag_rsv
      #   @return [Boolean] reserved bit from flags
      # @!attribute flag_df
      #   @return [Boolean] Don't Fragment flag 
      # @!attribute flag_mf
      #   @return [Boolena] More Fragment flags
      # @!attribute fragment_offset
      #   @return [Integer] 13-bit fragment offset
      define_bit_fields_on :frag, :flag_rsv, :flag_df, :flag_mf, :fragment_offset, 13

      # Read a IP header from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        return self if str.nil?
        raise ParseError, 'string too short for IP' if str.size < self.sz
        force_binary str
        self[:u8].read str[0, 1]
        self[:tos].read str[1, 1]
        self[:length].read str[2, 2]
        self[:id].read str[4, 2]
        self[:frag].read str[6, 2]
        self[:ttl].read str[8, 1]
        self[:protocol].read str[9, 1]
        self[:checksum].read str[10, 2]
        self[:src].read str[12, 4]
        self[:dst].read str[16, 4]
        self[:body].read str[20..-1]
        self
      end

       # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        checksum = (self[:u8].to_i << 8) | self.tos
        checksum += self.length
        checksum += self.id
        checksum += self.frag
        checksum += (self.ttl << 8) | self.protocol
        checksum += (self[:src].to_i >> 16)
        checksum += (self[:src].to_i & 0xffff)
        checksum += self[:dst].to_i >> 16
        checksum += self[:dst].to_i & 0xffff
        checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = ~(checksum % 0xffff ) & 0xffff
        self[:checksum].value = (checksum == 0) ? 0xffff : checksum
      end

      # Compute length and set +length+ field
      # @return [Integer]
      def calc_length
        self[:length].value = self.sz
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

      # Getter for length attribute
      # @return [Integer]
      def length
        self[:length].to_i
      end

      # Setter for length attribute
      # @param [Integer] length
      # @return [Integer]
      def length=(length)
        self[:length].value = length
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

      # Getter for protocol attribute
      # @return [Integer]
      def protocol
        self[:protocol].to_i
      end

      # Setter for  protocol attribute
      # @param [Integer] protocol
      # @return [Integer]
      def protocol=(protocol)
        self[:protocol].value = protocol
      end

      # Getter for checksum attribute
      # @return [Integer]
      def checksum
        self[:checksum].to_i
      end

      # Setter for  checksum attribute
      # @param [Integer] checksum
      # @return [Integer]
      def checksum=(checksum)
        self[:checksum].value = checksum
      end

      # Get IP source address
      # @return [String] dotted address
      def src
        self[:src].to_human
      end
      alias :source :src

      # Set IP source address
      # @param [String] addr dotted IP address
      # @return [String]
      def src=(addr)
        self[:src].from_human addr
      end
      alias :source= :src=

      # Get IP destination address
      # @return [String] dotted address
      def dst
        self[:dst].to_human
      end
      alias :destination :dst

      # Set IP destination address
      # @param [String] addr dotted IP address
      # @return [String]
      def dst=(addr)
        self[:dst].from_human addr
      end
      alias :destination= :dst=

      # Get IP part of pseudo header checksum.
      # @return [Integer]
      def pseudo_header_checksum
        checksum = self[:src].to_i + self[:dst].to_i
        (checksum >> 16) + (checksum & 0xffff)
      end

      # Send IP packet on wire.
      #
      # When sending packet at IP level, +checksum+ and +length+ fields are set by
      # kernel, so bad IP packets cannot be sent this way. To do so, use {Eth#to_w}.
      # @param [String,nil] iface interface name. Not used
      # @return [void]
      def to_w(iface=nil)
        sock = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
        sockaddrin = Socket.sockaddr_in(0, dst)
        sock.send to_s, 0, sockaddrin
      end

      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        shift = Inspect.shift_level(2)
        to_h.each do |attr, value|
          next if attr == :body
          str << Inspect.inspect_attribute(attr, value, 2)
          if attr == :u8
            str << shift + Inspect::INSPECT_FMT_ATTR % ['', 'version', version]
            str << shift + Inspect::INSPECT_FMT_ATTR % ['', 'ihl', ihl]
          elsif attr == :frag
            flags = flag_rsv? ? %w(RSV) : []
            flags << 'DF' if flag_df?
            flags << 'MF' if flag_mf?
            flags_str = flags.empty? ? 'none' : flags.join(',')
            str << shift + Inspect::INSPECT_FMT_ATTR % ['', 'flags', flags_str]
            foff = Inspect.int_dec_hex(fragment_offset, 4)
            str << shift + Inspect::INSPECT_FMT_ATTR % ['', 'frag_offset', foff]
          end
        end
        str
      end
    end

    Eth.bind_header IP, ethertype: 0x800
    IP.bind_header IP, protocol: 4
  end
end
