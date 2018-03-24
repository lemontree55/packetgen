# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
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
      # * a {#hello_interval} field ({Types::Int16}),
      # * an {#options} field ({Types::Int8}),
      # * a {#priority} field ({Types::Int8}),
      # * a {#dead_interval} field ({Types::Int32}),
      # * a {#designated_router} field ({IP::Addr}),
      # * a {#backup_designated_router} field ({IP::Addr}),
      # * a {#neighbors} array containing neighbors as {IP::Addr}.
      #
      # @author Sylvain Daubert
      class Hello < Base
        # @!attribute network_mask
        #  The network mask associated with this interface.
        #  @return [String]
        define_field :network_mask, IP::Addr
        # @!attribute hello_interval
        #  The number of seconds between this router's Hello packets.
        #  @return [Integer]
        define_field :hello_interval, Types::Int16

        # @!macro define_options
        OSPFv2.define_options(self)

        # @!attribute priority
        #  This router's Router Priority.  Used in (Backup) Designated
        #  Router election.
        #  @return [Integer]
        define_field :priority, Types::Int8
        # @!attribute dead_interval
        #  The number of seconds before declaring a silent router down.
        #  @return [Integer]
        define_field :dead_interval, Types::Int32
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
    
    self.add_class OSPFv2::Hello
    OSPFv2.bind_header OSPFv2::Hello, type: OSPFv2::TYPES['HELLO']
  end
end
