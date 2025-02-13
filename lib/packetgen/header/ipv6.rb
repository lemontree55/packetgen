# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require 'ipaddr'

module PacketGen
  module Header
    # IPv6 ({https://tools.ietf.org/html/rfc8200 RFC 8200})
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |Version| Traffic Class |           Flow Label                  |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |         Payload Length        |  Next Header  |   Hop Limit   |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   +                                                               +
    #   |                                                               |
    #   +                         Source Address                        +
    #   |                                                               |
    #   +                                                               +
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   +                                                               +
    #   |                                                               |
    #   +                      Destination Address                      +
    #   |                                                               |
    #   +                                                               +
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # A IPv6 header consists of:
    # * a first 32-bit word ({#u32}, of {BinStruct::Int32} type) composed of:
    #   * a 4-bit {#version} field,
    #   * a 8-bit {#traffic_class} field,
    #   * a 20-bit {#flow_label} field,
    # * a payload length field ({#length}, {BinStruct::Int16} type}),
    # * a next header field ({#next}, {BinStruct::Int8} type),
    # * a hop-limit field ({#hop}, +Int8+ type),
    # * a source address field ({#src}, {IPv6::Addr} type),
    # * a destination address field ({#dst}, +IPv6::Addr+ type),
    # * and a {#body} ({BinStruct::String} type).
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
    #
    # == Add IPv6 extensions
    # In IPv6, optional extensions are encoded in separate headers that
    # may be placed between the IPv6 header and the upper-layer header.
    #
    # In PacketGen, a IPv6 extension is processedf as a classical header:
    #  pkt = PacketGen.gen('IPv6')
    #  # Add a HopByHop extension
    #  pkt.add('IPv6::HopByHop')
    #  pkt.ipv6_hopbyhop.options << { type: 'router_alert', value: [0].pack('n') }
    #  # Add another header
    #  pkt.add('UDP')
    # @author Sylvain Daubert
    class IPv6 < Base; end

    require_relative 'ipv6/addr'

    class IPv6
      # IPv6 Ether type
      ETHERTYPE = 0x86dd

      # @!attribute u32
      #  First 32-bit word of IPv6 header
      #  @return [Integer]
      # @!attribute version
      #   @return [Integer] 4-bit version attribute
      # @!attribute traffic_class
      #   @return [Integer] 8-bit traffic_class attribute
      # @!attribute flow_label
      #   @return [Integer] 20-bit flow_label attribute
      define_bit_attr :u32, default: 0x60000000, version: 4, traffic_class: 8, flow_label: 20
      # @!attribute length
      #  16-bit word of IPv6 payload length
      #  @return [Integer]
      define_attr :length, BinStruct::Int16
      # @!attribute next
      #  8-bit IPv6 next payload value
      #  @return [Integer]
      define_attr :next, BinStruct::Int8
      # @!attribute hop
      #  8-bit IPv6 hop limit
      #  @return [Integer]
      define_attr :hop, BinStruct::Int8, default: 64
      # @!attribute src
      #  IPv6 source address
      #  @return [Addr]
      define_attr :src, Addr, default: '::1'
      # @!attribute dst
      #  IPv6 destination address
      #  @return [Addr]
      define_attr :dst, Addr, default: '::1'
      # @!attribute body
      #  @return [BinStruct::String,Header::Base]
      define_attr :body, BinStruct::String

      # Compute length and set +len+ field
      # @return [Integer]
      def calc_length
        Base.calculate_and_set_length self, header_in_size: false
      end

      # Get IPv6 part of pseudo header checksum.
      # @return [Integer]
      def pseudo_header_checksum
        sum = 0
        self[:src].to_a.each { |word| sum += word.to_i }
        self[:dst].to_a.each { |word| sum += word.to_i }
        sum
      end

      # Send IPv6 packet on wire. All attributes may be set (even {#version}).
      # @param [String] _iface interface name (not used)
      # @return [void]
      # @since 3.0.0 no more limitations on +flow_label+, +length+ and +src+ fields.
      def to_w(_iface=nil)
        sock = Socket.new(Socket::AF_INET6, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
        sockaddrin = Socket.sockaddr_in(0, dst)
        sock.send(to_s, 0, sockaddrin)
        sock.close
      end

      # @return [String]
      def inspect
        super do |attr|
          next unless attr == :u32

          str = Inspect.inspect_attribute(attr, self[attr])
          shift = Inspect.shift_level
          str << shift + Inspect::FMT_ATTR % ['', 'version', version]
          tclass = Inspect.int_dec_hex(traffic_class, 2)
          str << shift + Inspect::FMT_ATTR % ['', 'tclass', tclass]
          fl_value = Inspect.int_dec_hex(flow_label, 5)
          str << shift + Inspect::FMT_ATTR % ['', 'flow_label', fl_value]
        end
      end

      # Check version field
      # @see [Base#parse?]
      def parse?
        version == 6
      end

      # Invert source and destination addresses
      # @return [self]
      # @since 2.7.0
      def reply!
        self[:src], self[:dst] = self[:dst], self[:src]
        self
      end
    end

    self.add_class IPv6

    Eth.bind IPv6, ethertype: IPv6::ETHERTYPE
    SNAP.bind IPv6, proto_id: IPv6::ETHERTYPE
    Dot1q.bind IPv6, ethertype: IPv6::ETHERTYPE
    IP.bind IPv6, protocol: 41 # 6to4
  end
end

require_relative 'ipv6/extension'

module PacketGen
  module Header
    class IPv6
      class << self
        alias old_bind bind

        # Bind a upper header to IPv6 and its defined extension headers.
        # @see Base.bind
        def bind(header_klass, args={})
          IPv6.old_bind header_klass, args
          [IPv6::HopByHop].each do |klass|
            klass.bind header_klass, args
          end
        end
      end
    end
  end
end
