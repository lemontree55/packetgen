# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'ipaddr'

module PacketGen
  module Header

    # A IPv6 header consists of:
    # * a first 32-bit word ({#u32}, of {Types::Int32} type) composoed of:
    #   * a 4-bit {#version} field,
    #   * a 8-bit {#traffic_class} field,
    #   * a 20-bit {#flow_label} field,
    # * a payload length field ({#length}, {Types::Int16} type}),
    # * a next header field ({#next}, {Types::Int8} type),
    # * a hop-limit field ({#hop}, +Int8+ type),
    # * a source address field ({#src}, {IPv6::Addr} type),
    # * a destination address field ({#dst}, +IPv6::Addr+ type),
    #
    # == Create a IPv6 header
    #  # standalone
    #  ipv6 = PacketGen::Header::IPv6.new
    #  # in a packet
    #  pkt = PacketGen.gen('IPv6')
    #  # access to IPv6 header
    #  pkt.ipv6   # => PacketGen::Header::IPv6
    #
    # == IPv6 attributes
    #  ipv6.u32 = 0x60280001
    #  # the same as
    #  ipv6.version = 6
    #  ipv6.traffic_class = 2
    #  ipv6.flow_label = 0x80001
    #
    #  ipv6.length = 0x43
    #  ipv6.hop = 0x40
    #  ipv6.next = 6
    #  ipv6.src = '::1'
    #  ipv6.src                # => "::1"
    #  ipv6[:src]              # => PacketGen::Header::IPv6::Addr
    #  ipv6.dst = '2001:1234:5678:abcd::123'
    #  ipv6.body.read 'this is a body'
    # @author Sylvain Daubert
    class IPv6 < Base

      # IPv6 address, as a group of 8 2-byte words
      # @author Sylvain Daubert
      class Addr < Base

        # @!attribute a1
        #  1st 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a1, Types::Int16
        # @!attribute a2
        #  2nd 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a2, Types::Int16
        # @!attribute a3
        #  3rd 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a3, Types::Int16
        # @!attribute a4
        #  4th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a4, Types::Int16
        # @!attribute a5
        #  5th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a5, Types::Int16
        # @!attribute a6
        #  6th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a6, Types::Int16
        # @!attribute a7
        #  7th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a7, Types::Int16
        # @!attribute a8
        #  8th 2-byte word of IPv6 address
        #  @return [Integer]
        define_field :a8, Types::Int16

        # Read a colon-delimited address
        # @param [String] str
        # @return [self]
        def from_human(str)
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

        # Addr6 in human readable form (colon-delimited hex string)
        # @return [String]
        def to_human
          IPAddr.new(to_a.map { |a| a.to_i.to_s(16) }.join(':')).to_s
        end

        # Return an array of address 16-bit words
        # @return [Array<Integer>]
        def to_a
          @fields.values
        end
      end

      # @!attribute u32
      #  First 32-bit word of IPv6 header
      #  @return [Integer]
      define_field :u32, Types::Int32, default: 0x6000_0000
      # @!attribute length
      #  16-bit word of IPv6 payload length
      #  @return [Integer]
      define_field :length, Types::Int16
      # @!attribute next
      #  8-bit IPv6 next payload value
      #  @return [Integer]
      define_field :next, Types::Int8
      # @!attribute hop
      #  8-bit IPv6 hop limit
      #  @return [Integer]
      define_field :hop, Types::Int8, default: 64
      # @!attribute src
      #  IPv6 source address
      #  @return [Addr]
      define_field :src, Addr, default: '::1'
      # @!attribute dst
      #  IPv6 destination address
      #  @return [Addr]
      define_field :dst, Addr, default: '::1'
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

      # @!attribute version
      #   @return [Integer] 4-bit version attribute
      # @!attribute traffic_class
      #   @return [Integer] 8-bit traffic_class attribute
      # @!attribute flow_label
      #   @return [Integer] 20-bit flow_label attribute
      define_bit_fields_on :u32, :version, 4, :traffic_class, 8, :flow_label, 20

      # Compute length and set +len+ field
      # @return [Integer]
      def calc_length
        self.length = body.sz
      end

      # Get IPv6 part of pseudo header checksum.
      # @return [Integer]
      def pseudo_header_checksum
        sum = 0
        self[:src].to_a.each { |word| sum += word.to_i }
        self[:dst].to_a.each { |word| sum += word.to_i }
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

      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        to_h.each do |attr, value|
          next if attr == :body
          str << Inspect.inspect_attribute(attr, value, 2)
          if attr == :u32
            shift = Inspect.shift_level(2)
            str << shift + Inspect::INSPECT_FMT_ATTR % ['', 'version', version]
            tclass = Inspect.int_dec_hex(traffic_class, 2)
            str << shift + Inspect::INSPECT_FMT_ATTR % ['', 'tclass', tclass]
            fl_value = Inspect.int_dec_hex(flow_label, 5)
            str << shift + Inspect::INSPECT_FMT_ATTR % ['', 'flow_label', fl_value]
          end
        end
        str
      end
    end

    self.add_class IPv6

    Eth.bind_header IPv6, ethertype: 0x86DD
    IP.bind_header IPv6, protocol: 41    # 6to4
  end
end
