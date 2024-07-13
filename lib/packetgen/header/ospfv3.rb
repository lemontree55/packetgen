# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # This class supports OSPFv3 (RFC 5340).
    # A OSPFv3 header has the following format:
    #
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |   Version #   |     Type      |         Packet length         |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                         Router ID                             |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                          Area ID                              |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |          Checksum             |  Instance ID  |      0        |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # An OSPFv3 header consists of:
    # * a {#version} field ({Types::Int8}),
    # * a {#type} field ({Types::Int8Enum}),
    # * a {#length} field ({Types::Int16}). The length includes the header,
    # * a {#router_id} field ({Types::Int32}),
    # * an {#area_id} field ({Types::Int32}),
    # * a {#checksum} field ({Types::Int16}),
    # * an {#instance_id} field ({Types::Int8}),
    # * a {#reserved} field ({Types::Int8}),
    # * and a {#body} ({Types::String}).
    #
    # == Create an OSPFv3 header
    #   # standalone
    #   ospf = PacketGen::Header::OSPFv3.new
    #   # in a packet
    #   pkt = PacketGen.gen('IPv6', src: source_ip).add('OSPFv3')
    #   # make IPv6 header correct for OSPF
    #   pkt.ospfize
    #   # or make it correct with specific destination address
    #   pkt.ospfize(dst: :all_spf_routers)
    #   # access to OSPF header
    #   pkt.ospfv3    # => PacketGen::Header::OSPFv3
    #
    # == OSPFv3 attributes
    #  ospf.version              # => 3
    #  ospf.type = 'LS_ACK'      # or 5
    #  ospf.length = 154
    #  ospf.router_id = 0xc0a80001
    #  ospf.area_id = 1
    #  ospf.checksum = 0xabcd
    #  ospf.instance_id = 0
    #
    # == OSPFv3 body
    # OSPFv3 {#body} should contain OSPF payload for given {#type}:
    # * {OSPFv3::Hello},
    # * {OSPFv3::DbDescription},
    # * {OSPFv3::LSRequest},
    # * {OSPFv3::LSUpdate},
    # * or {OSPFv3::LSAck}.
    # @author Sylvain Daubert
    # @since 2.5.0
    class OSPFv3 < Base
      # IP protocol number for OSPF
      IP_PROTOCOL = OSPFv2::IP_PROTOCOL

      # OSPF packet types
      TYPES = OSPFv2::TYPES

      # @!attribute version
      #  8-bit OSPF version
      #  @return [Integer]
      define_field :version, Types::Int8, default: 3
      # @!attribute type
      #  8-bit OSPF packet type. Types are defined in {TYPES}.
      #  @return [Integer]
      define_field :type, Types::Int8Enum, enum: TYPES
      # @!attribute length
      #  16-bit OSPF packet length
      #  @return [Integer]
      define_field :length, Types::Int16
      # @!attribute router_id
      #  32-bit router ID
      #  @return [Integer]
      define_field :router_id, Types::Int32
      # @!attribute area_id
      #  32-bit area ID
      #  @return [Integer]
      define_field :area_id, Types::Int32
      # @!attribute checksum
      #  16-bit OSPF packet checksum
      #  @return [Integer]
      define_field :checksum, Types::Int16
      # @!attribute instance_id
      #  8-bit instance ID.
      #  @return [Integer]
      define_field :instance_id, Types::Int8
      # @!attribute reserved
      #  8-bit reserved field.
      #  @return [Integer]
      define_field :reserved, Types::Int8, default: 0
      # @!attribute body
      #  @return [String,Base]
      define_field :body, Types::String

      # @api private
      # Helper class method to define an OSPFv3 options field.
      # @param [Base] hdr header on which define a OSPFv3 options field
      # @return [void]
      # @!macro [attach] define_ospfv3_options
      #  @!attribute options
      #    24-bit options field. Handle {#v6_opt}, {#e_opt}, {#x_opt},
      #    {#n_opt}, {#r_opt} and {#dc_opt}.
      #    @return [Integer]
      #  @!attribute dc_opt
      #    This bit describes the router's handling of demand circuits.
      #    @return [Boolean]
      #  @!attribute r_opt
      #    This bit indicates whether the originator is an active router.
      #    @return [Boolean]
      #  @!attribute n_opt
      #    This bit indicates whether or not the router is attached to an NSSA.
      #    @return [Boolean]
      #  @!attribute x_opt
      #    This bit should be set to 0, and ignored when received.
      #    @return [Boolean]
      #  @!attribute e_opt
      #    This bit describes the way AS-external-LSAs are flooded.
      #    @return [Boolean]
      #  @!attribute v6_opt
      #    If this bit is clear, the router/link should be excluded from IPv6
      #    routing calculations.
      #    @return [Boolean]
      def self.define_options(hdr)
        hdr.define_field :options, Types::Int24
        hdr.define_bit_fields_on :options, :z, 18, :dc_opt, :r_opt,
                                 :n_opt, :x_opt, :e_opt, :v6_opt
      end

      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      def added_to_packet(packet)
        ospf_idx = packet.headers.size
        packet.instance_eval "def ospfize(**kwargs) @headers[#{ospf_idx}].ospfize(**kwargs); end" # def ospfize(**kwargs) @headers[2].ospfize(**kwargs); end
      end

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        ipv6 = ip_header(self)
        sum = ipv6.pseudo_header_checksum
        sum += IP_PROTOCOL
        sum += self.sz
        sum += IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end

      # Get human-readable type
      # @return [String]
      def human_type
        self[:type].to_human
      end

      # Compute length and set +length+ field
      # @return [Integer]
      def calc_length
        self[:length].value = Base.calculate_and_set_length(self)
      end

      # Fixup IPv6 header according to RFC 5340:
      # * set Traffic Class field to 0xc0,
      # * optionally set destination address,
      # * set Hop-limit to 1 if destination is a mcast address.
      # This method may be called as:
      #    # first way
      #    pkt.ospfv3.ospfize
      #    # second way
      #    pkt.ospfize
      # @param [String,Symbol,nil] dst destination address. May be a dotted IP
      #   address (by example '224.0.0.5') or a Symbol (+:all_spf_routers+ or
      #   +:all_d_routers+)
      # @return [void]
      def ospfize(dst: nil)
        ipv6 = ip_header(self)
        ipv6.traffic_class = 0xc0
        dst = case dst
              when :all_spf_routers
                'ff02::5'
              when :all_d_routers
                'ff02::6'
              else
                dst
              end
        ipv6.dst = dst unless dst.nil?
        ipv6.hop = 1 if ipv6[:dst].mcast?
      end
    end

    self.add_class OSPFv3
    IPv6.bind OSPFv3, next: OSPFv3::IP_PROTOCOL
  end
end

require_relative 'ospfv3/ipv6_prefix'
require_relative 'ospfv3/lsa_header'
require_relative 'ospfv3/lsa'
require_relative 'ospfv3/hello'
require_relative 'ospfv3/db_description'
require_relative 'ospfv3/ls_request'
require_relative 'ospfv3/ls_update'
require_relative 'ospfv3/ls_ack'
