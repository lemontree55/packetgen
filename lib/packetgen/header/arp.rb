# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    # An ARP header consists of:
    # * a hardware type ({#hrd} or {#htype}) field ({Types::Int16}),
    # * a protocol type ({#pro} or {#ptype}) field (+Int16+),
    # * a hardware address length ({#hln} or {#hlen}) field ({Types::Int8}),
    # * a protocol address length ({#pln} or {#plen}) field (+Int8+),
    # * a {#opcode} (or {#op}) field (+Int16+),
    # * a source hardware address ({#sha} or {#src_mac}) field ({Eth::MacAddr}),
    # * a source protocol address ({#spa} or {#src_ip}) field ({IP::Addr}),
    # * a target hardware address ({#tha} or {#dst_mac}) field (+Eth::MacAddr+),
    # * a target protocol address ({#tpa} or {#dst_ip}) field (+IP::Addr+),
    # * and a {#body}.
    #
    # == Create a ARP header
    #  # standalone
    #  arp = PacketGen::Header::ARP.new
    #  # in a packet
    #  pkt = PacketGen.gen('Eth').add('ARP')
    #  # access to ARP header
    #  pkt.arp   # => PacketGen::Header::ARP
    #
    # @author Sylvain Daubert
    class ARP < Base
      # @!attribute hrd
      #  16-bit hardware protocol type
      #  # @return [Integer]
      define_field :hrd, Types::Int16, default: 1
      # @!attribute pro
      #  16-bit internet protocol type
      #  # @return [Integer]
      define_field :pro, Types::Int16, default: 0x800
      # @!attribute hln
      #  8-bit hardware address length
      #  # @return [Integer]
      define_field :hln, Types::Int8, default: 6
      # @!attribute pln
      #  8-bit internet address length
      #  # @return [Integer]
      define_field :pln, Types::Int8, default: 4
      # @!attribute op
      #  16-bit operation code
      #  # @return [Integer]
      define_field :op, Types::Int16Enum, enum: { 'request' => 1, 'reply' => 2 }
      # @!attribute sha
      #  source hardware address
      #  @return [Eth::MacAddr]
      define_field :sha, Eth::MacAddr
      # @!attribute spa
      #  source protocol address
      #  @return [IP::Addr]
      define_field :spa, IP::Addr
      # @!attribute tha
      #  target hardware address
      #  @return [Eth::MacAddr]
      define_field :tha, Eth::MacAddr
      # @!attribute tpa
      #  target protocol address
      #  @return [IP::Addr]
      define_field :tpa, IP::Addr
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

      # @param [Hash] options
      # @option options [Integer] :hrd network protocol type (default: 1)
      # @option options [Integer] :pro internet protocol type (default: 0x800)
      # @option options [Integer] :hln length of hardware addresses (default: 6)
      # @option options [Integer] :pln length of internet addresses (default: 4)
      # @option options [Integer] :op operation performing by sender (default: 1).
      #   known values are +request+ (1) and +reply+ (2)
      # @option options [String] :sha sender hardware address
      # @option options [String] :spa sender internet address
      # @option options [String] :tha target hardware address
      # @option options [String] :tpa targetr internet address
      def initialize(options={})
        handle_options(options)
        super
      end

      alias htype hrd
      alias htype= hrd=
      alias ptype pro
      alias ptype= pro=
      alias hlen hln
      alias hlen= hln=
      alias plen pln
      alias plen= pln=
      alias opcode op
      alias opcode= op=
      alias src_mac sha
      alias src_mac= sha=
      alias src_ip spa
      alias src_ip= spa=
      alias dst_mac tha
      alias dst_mac= tha=
      alias dst_ip tpa
      alias dst_ip= tpa=

      # Invert data to create a reply.
      # @return [self]
      def reply!
        case opcode.to_i
        when 1
          self.opcode = 2
          invert_addresses
        when 2
          self.opcode = 1
          invert_addresses
          self[:tha].from_human('00:00:00:00:00:00')
        end
        self
      end

      private

      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      def handle_options(options)
        options[:hrd] ||= options[:htype]
        options[:pro] ||= options[:ptype]
        options[:hln] ||= options[:hlen]
        options[:pln] ||= options[:plen]
        options[:op]  ||= options[:opcode]
        options[:sha] ||= options[:src_mac]
        options[:spa] ||= options[:src_ip]
        options[:tha] ||= options[:dst_mac]
        options[:tpa] ||= options[:dst_ip]
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

      def invert_addresses
        self.spa, self.tpa = self.tpa, self.spa
        self.sha, self.tha = self.tha, self.sha
      end
    end

    self.add_class ARP

    Eth.bind ARP, ethertype: 0x806
    Dot1q.bind ARP, ethertype: 0x806
  end
end
