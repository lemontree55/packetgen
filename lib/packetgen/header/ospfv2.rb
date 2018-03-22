# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    
    # This class supports OSPFv2 (RFC 2328).
    # A OSPFv2 header has the following format:
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
    # * a {#version} field ({Types::Int8}),
    # * a {#type} field ({Types::Int8Enum}),
    # * a {#length} field ({Types::Int16}). The length includes the header,
    # * a {#router_id} field ({Types::Int32}),
    # * an {#area_id} field ({Types::Int32}),
    # * a {#checksum} field ({Types::Int16}),
    # * an {#au_type} field ({Types::Int16Enum}),
    # * an {#authentication} field ({Types::Int64}),
    # * and a {#body} ({Types::String}).
    #
    # == Create an OSPFv2 header
    #   # standalone
    #   ospf = PacketGen::Header::OSPFv2.new
    #   # in a packet
    #   pkt = PacketGen.gen('IP', src: source_ip).add('OSPFv2')
    #   # make IP header correct for OSPF
    #   pkt.ospfize
    #   # or make it correct with specific destination address
    #   pkt.ospfize(dst: :all_spf_routers)
    #   # access to OSPF header
    #   pkt.ospf    # => PacketGen::Header::OSPFv2
    #
    # == OSPFv2 attributes
    #  ospf.version              # => 2
    #  ospf.type = 'LS_ACK'      # or 5
    #  ospf.length = 154
    #  ospf.router_id = 0xc0a80001
    #  ospf.area_id = 1
    #  ospf.checksum = 0xabcd
    #  ospf.au_type = 'NO_AUTH'  # or 0
    #  ospf.authentication = 0
    #
    # == OSPFv2 body
    # OSPFv2 {#body} should contain OSPF payload for given {#type}.
    #
    # @author Sylvain Daubert
    class OSPFv2 < Base
      
      # IP protocol number for OSPF
      IP_PROTOCOL = 89
      
      # OSPF packet types
      TYPES    = {
        'HELLO'          => 1,
        'DB_DESCRIPTION' => 2,
        'LS_REQUEST'     => 3,
        'LS_UPDATE'      => 4,
        'LS_ACK'         => 5
      }

      # Authentication types
      AU_TYPES = {
        'NO_AUTH'         => 0,
        'PASSWORD'        => 1,
        'CRYPTO'          => 2,
        'CRYPTO_WITH_ESN' => 3
      }

      # @!attribute version
      #  8-bit OSPF version
      #  @return [Integer]
      define_field :version, Types::Int8, default: 2
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
      # @!attribute au_type
      #  16-bit authentication type. Types are defined in {AU_TYPES}.
      #  @return [Integer]
      define_field :au_type, Types::Int16Enum, enum: AU_TYPES
      # @!attribute authentication
      #  64-bit authentication data
      #  @return [Integer]
      define_field :authentication, Types::Int64
      # @!attribute body
      #  @return [String,Base]
      define_field :body, Types::String

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
      #    @return [Boolean]
      #  @!attribute o_opt
      #    @return [Boolean]
      #  @!attribute dc_opt
      #    This bit describes the router's handling of demand circuits.
      #    @return [Boolean]
      #  @!attribute l_opt
      #    This specifies if a LLS Data block is present.
      #    @return [Boolean]
      #  @!attribute n_opt
      #    This bit specifies if NSSA is supported.
      #    @return [Boolean]
      #  @!attribute mc_opt
      #    This bit describes whether IP multicast datagrams are forwarded.
      #    @return [Boolean]
      #  @!attribute e_opt
      #    This bit describes the way AS-external-LSAs are flooded.
      #    @return [Boolean]
      #  @!attribute mt_opt
      #    @return [Boolean]
      def self.define_options(hdr)
        hdr.define_field :options, Types::Int8
        hdr.define_bit_fields_on :options, :dn_opt, :o_opt, :dc_opt, :l_opt,
                                 :n_opt, :mc_opt, :e_opt, :mt_opt
      end

      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      def added_to_packet(packet)
        ospf_idx = packet.headers.size
        packet.instance_eval "def ospfize(**kwargs) @headers[#{ospf_idx}].ospfize(**kwargs); end"
      end

      # Compute checksum and set +checksum+ field
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

      # Compute length and set +length+ field
      # @return [Integer]
      def calc_length
        self[:length].value = Base.calculate_and_set_length(self)
      end

      # Fixup IP header according to RFC 2328:
      # * set TOS field to 0xc0,
      # * optionally sets destination address,
      # * set TTL to 1 if destination is a mcast address.
      # This method may be called as:
      #    # first method
      #    pkt.ospfv2.ospfize
      #    # second method
      #    pkt.ospfize
      # @param [String,Symbol,nil] dst destination address. May be a dotted IP
      #   address (by example '224.0.0.5') or a Symbol (:all_spf_routers or
      #   :all_d_routers)
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
    IP.bind_header OSPFv2, protocol: OSPFv2::IP_PROTOCOL
  end
end

require_relative 'ospfv2/hello'
require_relative 'ospfv2/lsa_header'
require_relative 'ospfv2/db_description'
require_relative 'ospfv2/ls_request'
