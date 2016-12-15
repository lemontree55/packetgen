# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'ipaddr'

module PacketGen
  module Header

    # IPv6 header class
    # @author Sylvain Daubert
    class IPv6 < Struct.new(:version, :traffic_class, :flow_label, :length,
                            :next, :hop, :src, :dst, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # IPv6 address, as a group of 8 2-byte words
      # @author Sylvain Daubert
      class Addr < Struct.new(:a1, :a2, :a3, :a4, :a5, :a6, :a7, :a8)
        include StructFu

        # @param [Hash] options
        # @option options [Integer] :a1
        # @option options [Integer] :a2
        # @option options [Integer] :a3
        # @option options [Integer] :a4
        # @option options [Integer] :a5
        # @option options [Integer] :a6
        # @option options [Integer] :a7
        # @option options [Integer] :a8
        def initialize(options={})
          super Int16.new(options[:a1]),
                Int16.new(options[:a2]),
                Int16.new(options[:a3]),
                Int16.new(options[:a4]),
                Int16.new(options[:a5]),
                Int16.new(options[:a6]),
                Int16.new(options[:a7]),
                Int16.new(options[:a8])
        end

        # Parse a colon-delimited address
        # @param [String] str
        # @return [self]
        def parse(str)
          return self if str.nil?
          addr = IPAddr.new(str)
          raise ArgumentError, 'string is not a IPv6 address' unless addr.ipv6?
          addri = addr.to_i
          self.a1 = addri >> 112
          self.a2 = addri >> 96 & 0xffff
          self.a3 = addri >> 80 & 0xffff
          self.a4 = addri >> 64 & 0xffff
          self.a5 = addri >> 48 & 0xffff
          self.a6 = addri >> 32 & 0xffff
          self.a7 = addri >> 16 & 0xffff
          self.a8 = addri & 0xffff
          self
        end

        # Read a Addr6 from a binary string
        # @param [String] str
        # @return [self]
        def read(str)
          force_binary str
          self[:a1].read str[0, 2]
          self[:a2].read str[2, 2]
          self[:a3].read str[4, 2]
          self[:a4].read str[6, 2]
          self[:a5].read str[8, 2]
          self[:a6].read str[10, 2]
          self[:a7].read str[12, 2]
          self[:a8].read str[14, 2]
          self
        end

        %i(a1 a2 a3 a4 a5 a6 a7 a8).each do |sym|
          class_eval "def #{sym}; self[:#{sym}].to_i; end\n" \
                     "def #{sym}=(v); self[:#{sym}].read v; end" 
        end

        # Addr6 in human readable form (colon-delimited hex string)
        # @return [String]
        def to_x
          IPAddr.new(to_a.map { |a| a.to_i.to_s(16) }.join(':')).to_s
        end
      end

      # @param [Hash] options
      # @option options [Integer] :version
      # @option options [Integer] :traffic_length
      # @option options [Integer] :flow_label
      # @option options [Integer] :length payload length
      # @option options [Integer] :next
      # @option options [Integer] :hop
      # @option options [String] :src colon-delimited source address
      # @option options [String] :dst colon-delimited destination address
      # @option options [String] :body binary string
      def initialize(options={})
        super options[:version] || 6,
              options[:traffic_class] || 0,
              options[:flow_label] || 0,
              Int16.new(options[:length]),
              Int8.new(options[:next]),
              Int8.new(options[:hop] || 64),
              Addr.new.parse(options[:src] || '::1'),
              Addr.new.parse(options[:dst] || '::1'),
              StructFu::String.new.read(options[:body])
      end

      # Read a IP header from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        return self if str.nil?
        raise ParseError, 'string too short for IPv6' if str.size < self.sz
        force_binary str
        first32 = str[0, 4].unpack('N').first
        self.version = first32 >> 28
        self.traffic_class = (first32 >> 20) & 0xff
        self.flow_label = first32 & 0xfffff

        self[:length].read str[4, 2]
        self[:next].read str[6, 1]
        self[:hop].read str[7, 1]
        self[:src].read str[8, 16]
        self[:dst].read str[24, 16]
        self[:body].read str[40..-1]
        self
      end

      # Compute length and set +len+ field
      # @return [Integer]
      def calc_length
        self.length = body.sz
      end

      # Getter for length attribute
      # @return [Integer]
      def length
        self[:length].to_i
      end

      # Setter for length attribute
      # @param [Integer] i
      # @return [Integer]
      def length=(i)
        self[:length].read i
      end

      # Getter for next attribute
      # @return [Integer]
      def next
        self[:next].to_i
      end

      # Setter for next attribute
      # @param [Integer] i
      # @return [Integer]
      def next=(i)
        self[:next].read i
      end

      # Getter for hop attribute
      # @return [Integer]
      def hop
        self[:hop].to_i
      end

      # Setter for hop attribute
      # @param [Integer] i
      # @return [Integer]
      def hop=(i)
        self[:hop].read i
      end

      # Getter for src attribute
      # @return [String]
      def src
        self[:src].to_x
      end
      alias :source :src

      # Setter for src attribute
      # @param [String] addr
      # @return [Integer]
      def src=(addr)
        self[:src].parse addr
      end
      alias :source= :src=

      # Getter for dst attribute
      # @return [String]
      def dst
        self[:dst].to_x
      end
      alias :destination :dst

      # Setter for dst attribute
      # @param [String] addr
      # @return [Integer]
      def dst=(addr)
        self[:dst].parse addr
      end
      alias :destination= :dst=

      # Get binary string
      # @return [String]
      def to_s
        first32 = (version << 28) | (traffic_class << 20) | flow_label
        [first32].pack('N') << to_a[3..-1].map { |field| field.to_s }.join
      end

      # Get IPv6 part of pseudo header sum.
      # @return [Integer]
      def pseudo_header_sum
        sum = 0
        self[:src].each { |word| sum += word.to_i }
        self[:dst].each { |word| sum += word.to_i }
        sum
      end
      
      # Send IPv6 packet on wire.
      #
      # When sending packet at IPv6 level, +version+, +flow_label+ and +length+
      # fields are set by kernel. Source address should be a unicast address
      # assigned to the host. To set any of this fields, use {Eth#to_w}.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface=nil)
        sock = Socket.new(Socket::AF_INET6, Socket::SOCK_RAW, self.next)
        sockaddrin = Socket.sockaddr_in(0, dst)

        # IPv6 RAW sockets don't have IPHDRINCL option to send IPv6 header.
        # So, header must be built using ancillary data.
        # Only src address, traffic_class and hop_limit can be set this way.
        hop_limit = Socket::AncillaryData.int(Socket::AF_INET6,
                                              Socket::IPPROTO_IPV6,
                                              Socket::IPV6_HOPLIMIT, hop)
        tc = Socket::AncillaryData.int(Socket::AF_INET6,
                                       Socket::IPPROTO_IPV6,
                                       Socket::IPV6_TCLASS,
                                       traffic_class)

        # src address is set through PKT_INFO, which needs interface index.
        ifaddr = Socket.getifaddrs.find { |ia| ia.name == iface }
        raise WireError, "unknown #{iface} interface" if ifaddr.nil?
        pkt_info = Socket::AncillaryData.ipv6_pktinfo(Addrinfo.ip(src), ifaddr.ifindex)

        sock.sendmsg body.to_s, 0, sockaddrin, hop_limit, tc, pkt_info
      end
    end

    Eth.bind_header IPv6, ethertype: 0x86DD
    IP.bind_header IPv6, protocol: 41    # 6to4
  end
end
