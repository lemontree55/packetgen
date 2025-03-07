# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # This class supports OSPFv2 (RFC 2328).
    # An OSPFv2 header has the following format:
    #
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |   Version #   |     Type      |         Packet length         |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                          Router ID                            |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                           Area ID                             |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |           Checksum            |             AuType            |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                       Authentication                          |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                       Authentication                          |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # An OSPFv2 header consists of:
    # * a {#version} field (+BinStruct::Int8+),
    # * a {#type} field (+BinStruct::Int8Enum+),
    # * a {#length} field (+BinStruct::Int16+). The length includes the header,
    # * a {#router_id} field (+BinStruct::Int32+),
    # * an {#area_id} field (+BinStruct::Int32+),
    # * a {#checksum} field (+BinStruct::Int16+),
    # * an {#au_type} field (+BinStruct::Int16Enum+),
    # * an {#authentication} field (+BinStruct::Int64+),
    # * and a {#body} (+BinStruct::String+ or {Headerable}).
    #
    # @example Create an OSPFv2 header
    #   # standalone
    #   ospf = PacketGen::Header::OSPFv2.new
    #   # in a packet
    #   pkt = PacketGen.gen('IP').add('OSPFv2')
    #   # make IP header correct for OSPF
    #   pkt.ospfize
    #   # or make it correct with specific destination address
    #   pkt.ospfize(dst: :all_spf_routers)
    #   # access to OSPF header
    #   pkt.ospfv2.class    # => PacketGen::Header::OSPFv2
    #
    # @example OSPFv2 attributes
    #   ospf = PacketGen::Header::OSPFv2.new
    #   ospf.version              # => 2
    #   ospf.type = 'LS_ACK'      # or 5
    #   ospf.length = 154
    #   ospf.router_id = 0xc0a80001
    #   ospf.area_id = 1
    #   ospf.checksum = 0xabcd
    #   ospf.au_type = 'NO_AUTH'  # or 0
    #   ospf.authentication = 0
    #
    # == OSPFv2 body
    # OSPFv2 {#body} should contain OSPF payload for given {#type}:
    # * {OSPFv2::Hello},
    # * {OSPFv2::DbDescription},
    # * {OSPFv2::LSRequest},
    # * {OSPFv2::LSUpdate},
    # * or {OSPFv2::LSAck}.
    #
    # @author Sylvain Daubert
    # @since 2.5.0
    class OSPFv2 < Base
      # IP protocol number for OSPF
      IP_PROTOCOL = 89

      # OSPF packet types
      TYPES = {
        'HELLO' => 1,
        'DB_DESCRIPTION' => 2,
        'LS_REQUEST' => 3,
        'LS_UPDATE' => 4,
        'LS_ACK' => 5
      }.freeze

      # Authentication types
      AU_TYPES = {
        'NO_AUTH' => 0,
        'PASSWORD' => 1,
        'CRYPTO' => 2,
        'CRYPTO_WITH_ESN' => 3
      }.freeze

      # @!attribute version
      #  8-bit OSPF version
      #  @return [Integer]
      define_attr :version, BinStruct::Int8, default: 2
      # @!attribute type
      #  8-bit OSPF packet type. Types are defined in {TYPES}.
      #  @return [Integer]
      define_attr :type, BinStruct::Int8Enum, enum: TYPES
      # @!attribute length
      #  16-bit OSPF packet length
      #  @return [Integer]
      define_attr :length, BinStruct::Int16
      # @!attribute router_id
      #  32-bit router ID
      #  @return [Integer]
      define_attr :router_id, BinStruct::Int32
      # @!attribute area_id
      #  32-bit area ID
      #  @return [Integer]
      define_attr :area_id, BinStruct::Int32
      # @!attribute checksum
      #  16-bit OSPF packet checksum
      #  @return [Integer]
      define_attr :checksum, BinStruct::Int16
      # @!attribute au_type
      #  16-bit authentication type. Types are defined in {AU_TYPES}.
      #  @return [Integer]
      define_attr :au_type, BinStruct::Int16Enum, enum: AU_TYPES
      # @!attribute authentication
      #  64-bit authentication data
      #  @return [Integer]
      define_attr :authentication, BinStruct::Int64
      # @!attribute body
      #  OSPF body
      #  @return [String,Headerable]
      define_attr :body, BinStruct::String

      # @api private
      # Helper class method to define an OSPFv2 options field.
      # @param [Base] hdr header on which define a OSPFv2 options field
      # @return [void]
      # @!macro [attach] define_options
      #  @!attribute options
      #    8-bit options field. Handle {#mt_opt}, {#e_opt}, {#mc_opt},
      #    {#n_opt}, {#l_opt}, {#dc_opt}, {#o_opt} and {#dn_opt}.
      #    @return [Integer]
      #  @!attribute dn_opt
      #    @return [Integer]
      #  @!attribute o_opt
      #    @return [Integer]
      #  @!attribute dc_opt
      #    This bit describes the router's handling of demand circuits.
      #    @return [Integer]
      #  @!attribute l_opt
      #    This specifies if a LLS Data block is present.
      #    @return [Integer]
      #  @!attribute n_opt
      #    This bit specifies if NSSA is supported.
      #    @return [Integer]
      #  @!attribute mc_opt
      #    This bit describes whether IP multicast datagrams are forwarded.
      #    @return [Integer]
      #  @!attribute e_opt
      #    This bit describes the way AS-external-LSAs are flooded.
      #    @return [Integer]
      #  @!attribute mt_opt
      #    @return [Integer]
      def self.define_options(hdr)
        hdr.define_bit_attr :options, dn_opt: 1, o_opt: 1, dc_opt: 1, l_opt: 1, n_opt: 1, mc_opt: 1, e_opt: 1, mt_opt: 1
      end

      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      # @param [Packet] packet
      # @return [void]
      # Add +#ospfize+ method to +packet+. This method calls {#ospfize}.
      def added_to_packet(packet)
        ospf_idx = packet.headers.size
        packet.instance_eval "def ospfize(**kwargs) @headers[#{ospf_idx}].ospfize(**kwargs); end" # def ospfize(**kwargs) @headers[2].ospfize(**kwargs); end
      end

      # Compute checksum and set {#checksum} attribute
      # @return [Integer]
      def calc_checksum
        # #authentication field is not used in checksum calculation,
        # so force it to 0 before checksumming
        saved_auth = self.authentication
        self.authentication = 0

        sum = IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)

        # Restore #authentication value
        self.authentication = saved_auth

        self.checksum
      end

      # Get human-readable type
      # @return [String]
      def human_type
        self[:type].to_human
      end

      # Get human-readable AU type
      # @return [String]
      def human_au_type
        self[:au_type].to_human
      end

      # Compute length and set {#length} attribute
      # @return [Integer]
      def calc_length
        self[:length].value = Base.calculate_and_set_length(self)
      end

      # Fixup IP header according to RFC 2328:
      # * set TOS field to 0xc0,
      # * optionally set destination address,
      # * set TTL to 1 if destination is a mcast address.
      # This method may be called as:
      #    # first way
      #    pkt.ospfv2.ospfize
      #    # second way
      #    pkt.ospfize
      # @param [String,Symbolnil] dst destination address. May be a dotted IP
      #   address (by example '224.0.0.5') or a Symbol (+:all_spf_routers+ or
      #   +:all_d_routers+)
      # @return [void]
      def ospfize(dst: nil)
        ip = ip_header(self)
        ip.tos = 0xc0
        dst = case dst
              when :all_spf_routers
                '224.0.0.5'
              when :all_d_routers
                '224.0.0.6'
              else
                dst
              end
        ip.dst = dst unless dst.nil?
        ip.ttl = 1 if ip[:dst].mcast?
      end
    end

    self.add_class OSPFv2
    IP.bind OSPFv2, protocol: OSPFv2::IP_PROTOCOL
  end
end

require_relative 'ospfv2/hello'
require_relative 'ospfv2/lsa_header'
require_relative 'ospfv2/lsa'
require_relative 'ospfv2/db_description'
require_relative 'ospfv2/ls_request'
require_relative 'ospfv2/ls_update'
require_relative 'ospfv2/ls_ack'
