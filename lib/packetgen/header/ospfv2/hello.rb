# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv2
      # This class handles {OSPFv2 OSPFv2} HELLO packets payload. The HELLO
      # payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                        Network Mask                           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |         HelloInterval         |    Options    |    Rtr Pri    |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                     RouterDeadInterval                        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                      Designated Router                        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                   Backup Designated Router                    |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                          Neighbor                             |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                              ...                              |
      # A HELLO payload consists of:
      # * a {#network_mask} field ({IP::Addr}),
      # * a {#hello_interval} field (+BinStruct::Int16+),
      # * an {#options} field (+BinStruct::Int8+),
      # * a {#priority} field (+BinStruct::Int8+),
      # * a {#dead_interval} field (+BinStruct::Int32+),
      # * a {#designated_router} field ({IP::Addr}),
      # * a {#backup_designated_router} field ({IP::Addr}),
      # * a {#neighbors} array containing neighbors as {IP::Addr}.
      #
      # == Create a HELLO payload
      #   # standalone
      #   hello = PacketGen::Header::OSPFv2::Hello.new
      #   # in a packet
      #   pkt = PacketGen.gen('IP', src: source_ip).add('OSPFv2').add('OSPFv2::Hello')
      #   # make IP header correct for OSPF
      #   pkt.ospfize
      #   # access to Hello payload
      #   pkt.ospfv2_hello    # => PacketGen::Header::OSPFv2::Hello
      #
      # == HELLO attributes
      #   hello.network_mask = '255.255.255.0'
      #   hello.hello_interval = 10
      #   hello.options = 0
      #   hello.priority = 1
      #   hello.dead_interval = 300
      #   hello.designated_router = '10.0.0.1'
      #   hello.backup_designated_router = '0.0.0.0'
      #   # set neighbors identifiers
      #   hello.neighbors << '10.0.1.1'
      #   hello.neighbors << '10.0.2.1'
      # @author Sylvain Daubert
      class Hello < Base
        # @!attribute network_mask
        #  The network mask associated with this interface.
        #  @return [String]
        define_attr :network_mask, IP::Addr
        # @!attribute hello_interval
        #  The number of seconds between this router's Hello packets.
        #  @return [Integer]
        define_attr :hello_interval, BinStruct::Int16

        # @!macro define_options
        OSPFv2.define_options(self)

        # @!attribute priority
        #  This router's Router Priority.  Used in (Backup) Designated
        #  Router election.
        #  @return [Integer]
        define_attr :priority, BinStruct::Int8
        # @!attribute dead_interval
        #  The number of seconds before declaring a silent router down.
        #  @return [Integer]
        define_attr :dead_interval, BinStruct::Int32
        # @!attribute designated_router
        #  The identity of the Designated Router for this network, in the
        #  view of the sending router.
        #  @return [String]
        define_attr :designated_router, IP::Addr
        # @!attribute backup_designated_router
        #  The identity of the Backup Designated Router for this network,
        #  in the view of the sending router.
        #  @return [String]
        define_attr :backup_designated_router, IP::Addr
        # @!attribute neighbors
        #  Array of neighbors
        #  @return [IP::ArrayOfAddr]
        define_attr :neighbors, IP::ArrayOfAddr
      end
    end

    self.add_class OSPFv2::Hello
    OSPFv2.bind OSPFv2::Hello, type: OSPFv2::TYPES['HELLO']
  end
end
