# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    
    # Bootstrap Protocol, {https://tools.ietf.org/html/rfc951
    # RFC 951}
    #
    # A BOOTP header consists of:
    # * an operation code field ({#op} of type {Types::Int8Enum}),
    # * a hardware address type ({#htype} of type {Types::Int8}),
    # * a hardware address length ({#hlen} of type {Types::Int8}),
    # * a {#hops} field ({Types::Int8}),
    # * a transaction ID ({#xid} of type {Types::Int32}),
    # * a {#secs} field (){Types::Int16}),
    # * a {#flags} field (){Types::Int16}):
    #   * a 1-bit broadcast flag ({#b}),
    #   * a 15-bit Must Be Zero field ({#mbz}),
    # * a {#ciaddr} field ({IP::Addr}),
    # * a {#yiaddr} field ({IP::Addr}),
    # * a {#siaddr} field ({IP::Addr}),
    # * a {#giaddr} field ({IP::Addr}),
    # * a {#chaddr} field (16-byte {Types::String}),
    # * a {#sname} field (64-byte {Types::CString}),
    # * a {#file} field (128-byte {Types::CString}),
    # * and a body ({Types::String}).
    #
    # == Create a BOOTP header
    #   # standalone
    #   bootp = PacketGen::Header::BOOTP.new
    #   # in a packet
    #   pkt = PacketGen.gen('IP').add('BOOTP')
    #   # access to BOOTP header
    #   pkt.bootp      # => PacketGen::Header::BOOTP
    # @author Sylvain Daubert
    class BOOTP < Base
      
      UDP_SERVER_PORT = 67
      UDP_CLIENT_PORT = 68
      
      # DHCP opcodes
      OPCODES = {
        'BOOTREQUEST' => 1,
        'BOOTREPLY'   => 2
      }

      # @!attribute op
      #   8-bit opcode
      #   @return [Integer]
      define_field :op, Types::Int8Enum, enum: OPCODES

      # @!attribute htype
      #  8-bit hardware address type
      #  @return [Integer]
      define_field :htype, Types::Int8, default: 1

      # @!attribute hlen
      #  8-bit hardware address length
      #  @return [Integer]
      define_field :hlen, Types::Int8, default: 6

      # @!attribute hops
      #  @return [Integer]
      define_field :hops, Types::Int8

      # @!attribute xid
      #  32-bit Transaction ID
      #  @return [Integer]
      define_field :xid, Types::Int32
      
      # @!attribute secs
      #  16-bit integer: number of seconds elapsed since client began address
      #  acquisition or renewal process
      #  @return [Integer]
      define_field :secs, Types::Int16
      
      # @!attribute flags
      #  16-bit flag field
      #  @return [Integer]
      define_field :flags, Types::Int16

      # @!attribute ciaddr
      #  client IP address
      #  @return [String]
      define_field :ciaddr, IP::Addr

      # @!attribute yiaddr
      #  'your' (client) IP address
      #  @return [String]
      define_field :yiaddr, IP::Addr
      
      # @!attribute siaddr
      #  IP address of next server to use in bootstrap
      #  @return [String]
      define_field :siaddr, IP::Addr
      
      # @!attribute giaddr
      #  Relay agent IP address, used in booting via a relay agent
      #  @return [String]
      define_field :giaddr, IP::Addr
      
      # @!attribute chaddr
      #   client hardware address
      #   @return [String]
      define_field :chaddr, Types::String, static_length: 16

      # @!attribute sname
      #   optional server hostname, null-terminated string
      #   @return [String]
      define_field :sname, Types::CString, static_length: 64

      # @!attribute file
      #   Boot file name, null terminated string
      #   @return [String]
      define_field :file, Types::CString, static_length: 128

      # @!attribute body
      #   @return [String]
      define_field :body, Types::String
      
      # @!attribute b
      #  Broadcast flag, from {#flags}
      # @return [Boolean]
      # @!attribute mbz
      #  15-bit Must Be Zero bits, from {#flags}
      # @return [Boolean]
      define_bit_fields_on :flags, :b, :mbz, 15
      
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        fields.each do |attr|
          next if attr == :body
          next unless is_present?(attr)
          if attr == :chaddr and self.hlen == 6
            str << Inspect.inspect_attribute(attr, Eth::MacAddr.new.read(self[:chaddr][0, 6]), 2)
          else
            str << Inspect.inspect_attribute(attr, self[attr], 2)
          end
        end
        str
      end
    end
    
    UDP.bind_header BOOTP, sport: 67, dport: 68
    UDP.bind_header BOOTP, sport: 68, dport: 67
  end
end
