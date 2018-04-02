# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header

    # This class supports MLDv1 (RFC 2710).
    #
    # From RFC 2710, a MLD header has the following format:
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |    Maximum Response delay     |           Reserved            |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   +                                                               +
    #   |                                                               |
    #   +                       Multicast Address                       +
    #   |                                                               |
    #   +                                                               +
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # A MLD header consists of:
    # * a {#max_resp_delay} field ({Types::Int16} type),
    # * a {#reserved} field ({Types::Int16} type),
    # * a {#mcast_addr} field ({Header::IPv6::Addr} type),
    # * and a {#body} (unused for MLDv1).
    #
    # == Create a MLD header
    #  # standalone
    #  mld = PacketGen::Header::MLD.new
    #  # in a packet
    #  pkt = PacketGen.gen('IPv6').add('ICMPv6').add('MLD')
    #  # access to MLD header
    #  pkt.mld    # => PacketGen::Header::MLD
    #
    # == MLD attributes
    #  pkt.icmpv6.type = 130       # ICMPv6 type 130 is MLD Multicast Listener Query
    #  pkt.mld.max_resp_delay = 20
    #  pkt.mld.group_addr = '::'
    # @author Sylvain Daubert
    class MLD < Base
      # @!attribute max_resp_delay
      #  16-bit MLD Max Response Delay
      #  @return [Integer]
      define_field :max_resp_delay, Types::Int16
      alias max_resp_code max_resp_delay
      alias max_resp_code= max_resp_delay=
      # @!attribute reserved
      #  16-bit Reserved field
      #  @return [Integer]
      define_field :reserved, Types::Int16
      # @!attribute mcast_addr
      #  IPv6 Multicast address
      #  @return [IPv6::Addr]
      define_field :mcast_addr, IPv6::Addr, default: '::'
      # @!attribute body
      #  @return [String,Base]
      define_field :body, Types::String

      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      def added_to_packet(packet)
        mld_idx = packet.headers.size
        packet.instance_eval "def mldize() @headers[#{mld_idx}].mldize; end"
      end

      # Fixup IP header according to RFC 2710:
      # * set Hop limit to 1,
      # * add Router Alert option,
      # * recalculate checksum and length.
      # This method may be called as:
      #    # first method
      #    pkt.mld.mldize
      #    # second method
      #    pkt.mldize
      # @return [void]
      def mldize
        ipv6 = ip_header(self)
        ipv6.hop = 1
        ipv6.next = 0
        packet.insert(ipv6, 'IPv6::HopByHop', next: ICMPv6::IP_PROTOCOL)
        packet.ipv6_hopbyhop.options << { type: 'router_alert', value: [0].pack('n') }
        packet.calc
      end
    end
  end
end

# Add MLDv2::MLQ before MLD to priorize its decoding
require_relative 'mldv2'

PacketGen::Header.add_class PacketGen::Header::MLD
PacketGen::Header::ICMPv6.bind_header PacketGen::Header::MLD, type: 130
PacketGen::Header::ICMPv6.bind_header PacketGen::Header::MLD, type: 131
PacketGen::Header::ICMPv6.bind_header PacketGen::Header::MLD, type: 132
