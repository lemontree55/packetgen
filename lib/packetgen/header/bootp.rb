# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # Bootstrap Protocol, {https://tools.ietf.org/html/rfc951
    # RFC 951}
    #
    # A BOOTP header consists of:
    # * an operation code field ({#op} of type {BinStruct::Int8Enum}),
    # * a hardware address type ({#htype} of type {BinStruct::Int8}),
    # * a hardware address length ({#hlen} of type {BinStruct::Int8}),
    # * a {#hops} field ({BinStruct::Int8}),
    # * a transaction ID ({#xid} of type {BinStruct::Int32}),
    # * a {#secs} field (){BinStruct::Int16}),
    # * a {#flags} field (){BinStruct::Int16}):
    #   * a 1-bit broadcast flag ({#b}),
    #   * a 15-bit Must Be Zero field ({#mbz}),
    # * a {#ciaddr} field ({IP::Addr}),
    # * a {#yiaddr} field ({IP::Addr}),
    # * a {#siaddr} field ({IP::Addr}),
    # * a {#giaddr} field ({IP::Addr}),
    # * a {#chaddr} field (16-byte {BinStruct::String}),
    # * a {#sname} field (64-byte {BinStruct::CString}),
    # * a {#file} field (128-byte {BinStruct::CString}),
    # * and a body ({BinStruct::String}).
    #
    # == Create a BOOTP header
    #   # standalone
    #   bootp = PacketGen::Header::BOOTP.new
    #   # in a packet
    #   pkt = PacketGen.gen('IP').add('BOOTP')
    #   # access to BOOTP header
    #   pkt.bootp      # => PacketGen::Header::BOOTP
    # @author Sylvain Daubert
    # @since 2.2.0
    class BOOTP < Base
      UDP_SERVER_PORT = 67
      UDP_CLIENT_PORT = 68

      # DHCP opcodes
      OPCODES = {
        'BOOTREQUEST' => 1,
        'BOOTREPLY' => 2
      }.freeze

      # @!attribute op
      #   8-bit opcode
      #   @return [Integer]
      define_attr :op, BinStruct::Int8Enum, enum: OPCODES

      # @!attribute htype
      #  8-bit hardware address type
      #  @return [Integer]
      define_attr :htype, BinStruct::Int8, default: 1

      # @!attribute hlen
      #  8-bit hardware address length
      #  @return [Integer]
      define_attr :hlen, BinStruct::Int8, default: 6

      # @!attribute hops
      #  @return [Integer]
      define_attr :hops, BinStruct::Int8

      # @!attribute xid
      #  32-bit Transaction ID
      #  @return [Integer]
      define_attr :xid, BinStruct::Int32

      # @!attribute secs
      #  16-bit integer: number of seconds elapsed since client began address
      #  acquisition or renewal process
      #  @return [Integer]
      define_attr :secs, BinStruct::Int16

      # @!attribute flags
      #  16-bit flag field
      #  @return [Integer]
      define_attr :flags, BinStruct::Int16

      # @!attribute ciaddr
      #  client IP address
      #  @return [String]
      define_attr :ciaddr, IP::Addr

      # @!attribute yiaddr
      #  'your' (client) IP address
      #  @return [String]
      define_attr :yiaddr, IP::Addr

      # @!attribute siaddr
      #  IP address of next server to use in bootstrap
      #  @return [String]
      define_attr :siaddr, IP::Addr

      # @!attribute giaddr
      #  Relay agent IP address, used in booting via a relay agent
      #  @return [String]
      define_attr :giaddr, IP::Addr

      # @!attribute chaddr
      #   client hardware address
      #   @return [String]
      define_attr :chaddr, BinStruct::String, static_length: 16

      # @!attribute sname
      #   optional server hostname, null-terminated string
      #   @return [String]
      define_attr :sname, BinStruct::CString, static_length: 64

      # @!attribute file
      #   Boot file name, null terminated string
      #   @return [String]
      define_attr :file, BinStruct::CString, static_length: 128

      # @!attribute body
      #   @return [String]
      define_attr :body, BinStruct::String

      # @!attribute b
      #  Broadcast flag, from {#flags}
      # @return [Boolean]
      # @!attribute mbz
      #  15-bit Must Be Zero bits, from {#flags}
      # @return [Boolean]
      define_bit_attrs_on :flags, :b, :mbz, 15

      # @return [String]
      def inspect
        super do |attr|
          next unless (attr == :chaddr) && (self.hlen == 6)

          Inspect.inspect_attribute(attr, Eth::MacAddr.new.read(self[:chaddr][0, 6]))
        end
      end

      # Invert opcode, if known
      # @return [self]
      def reply!
        case self.op
        when 1 then self.op = 2
        when 2 then self.op = 1
        end
        self
      end
    end

    UDP.bind BOOTP, sport: 67, dport: 68
    UDP.bind BOOTP, sport: 68, dport: 67
  end
end
