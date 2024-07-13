# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3
      # This class handles {OSPFv3 OSPFv3} HELLO packets payload. The HELLO
      # payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                        Interface ID                           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Rtr Priority  |             Options                           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        HelloInterval          |       RouterDeadInterval      |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                   Designated Router ID                        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                Backup Designated Router ID                    |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         Neighbor ID                           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                        ...                                    |
      # A HELLO payload consists of:
      # * a {#interface_id} field ({Types::Int32}),
      # * a {#priority} field ({Types::Int8}),
      # * an {#options} field ({Types::Int24}),
      # * a {#hello_interval} field ({Types::Int16}),
      # * a {#dead_interval} field ({Types::Int16}),
      # * a {#designated_router} field ({IP::Addr}),
      # * a {#backup_designated_router} field ({IP::Addr}),
      # * a {#neighbors} array containing neighbors as {IP::Addr}.
      #
      # == Create a HELLO payload
      #   # standalone
      #   hello = PacketGen::Header::OSPFv3::Hello.new
      #   # in a packet
      #   pkt = PacketGen.gen('IPv6', src: source_ip).add('OSPFv3').add('OSPFv3::Hello')
      #   # make IPv6 header correct for OSPF
      #   pkt.ospfize
      #   # access to Hello payload
      #   pkt.ospfv3_hello    # => PacketGen::Header::OSPFv3::Hello
      #
      # == HELLO attributes
      #   hello.interface_id = 1
      #   hello.priority = 1
      #   # set options. Options may also be set one by one with #v6_opt, #e_opt,
      #   # #n_opt, #r_opt and #dc_opt
      #   hello.options = 0x33
      #   hello.hello_interval = 10
      #   hello.dead_interval = 300
      #   hello.designated_router = '0.0.0.1'
      #   hello.backup_designated_router = '0.0.0.2'
      #   # set neighbors identifiers
      #   hello.neighbors << '1.1.1.1'
      #   hello.neighbors << '2.2.2.2'
      # @author Sylvain Daubert
      class Hello < Base
        # @!attribute interface_id
        #  The network mask associated with this interface.
        #  @return [String]
        define_field :interface_id, Types::Int32
        # @!attribute priority
        #  This router's Router Priority.  Used in (Backup) Designated
        #  Router election.
        #  @return [Integer]
        define_field :priority, Types::Int8
        # @!macro define_ospfv3_options
        OSPFv3.define_options(self)
        # @!attribute hello_interval
        #  The number of seconds between this router's Hello packets.
        #  @return [Integer]
        define_field :hello_interval, Types::Int16
        # @!attribute dead_interval
        #  The number of seconds before declaring a silent router down.
        #  @return [Integer]
        define_field :dead_interval, Types::Int16
        # @!attribute designated_router
        #  The identity of the Designated Router for this network, in the
        #  view of the sending router.
        #  @return [String]
        define_field :designated_router, IP::Addr
        # @!attribute backup_designated_router
        #  The identity of the Backup Designated Router for this network,
        #  in the view of the sending router.
        #  @return [String]
        define_field :backup_designated_router, IP::Addr
        # @!attribute neighbors
        #  Array of neighbors
        #  @return [IP::ArrayOfAddr]
        define_field :neighbors, IP::ArrayOfAddr
      end
    end

    self.add_class OSPFv3::Hello
    OSPFv3.bind OSPFv3::Hello, type: OSPFv3::TYPES['HELLO']
  end
end
