# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # Generic Routing Encapsulation (RFC 2784 and 2890)
    #                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |C| |K|S| Reserved0       | Ver |         Protocol Type         |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |      Checksum (optional)      |       Reserved1 (Optional)    |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                         Key (optional)                        |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                 Sequence Number (Optional)                    |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # @author Sylvain Daubert
    class GRE < Base

      # IP protocol number for GRE
      IP_PROTOCOL = 47

      define_field :u16, Types::Int16

      # @!attribute c
      #   @return [Boolean]
      # @!attribute k
      #   @return [Boolean]
      # @!attribute s
      #   @return [Boolean]
      # @!attribute reserved0
      #   @return [Integer]
      # @!attribute ver
      #   @return [Integer]
      define_bit_fields_on :u16, :c, :r, :k, :s, :reserved0, 9, :ver, 3

      # @!attribute protocol_type
      #   @return [Integer]
      define_field :protocol_type, Types::Int16
      # @!attribute checksum
      #   @return [Integer]
      define_field :checksum, Types::Int16, default: 0, optional: ->(gre) { gre.c? }
      # @!attribute reserved1
      #   @return [Integer]
      define_field :reserved1, Types::Int16, default: 0, optional: ->(gre) { gre.c? }
      # @!attribute key
      #   @return [Integer]
      define_field :key, Types::Int32, optional: ->(gre) { gre.k? }
      # @!attribute sequence_number
      #   @return [Integer]
      define_field :sequence_number, Types::Int32, optional: ->(gre) { gre.s? }
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

      alias seqnum sequence_number
      alias seqnum= sequence_number=

      def initialize(options={})
        opts = { r: false, reserved0: 0, version: 0 }.merge(options)
        super(opts)
      end

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end
    end

    self.add_class GRE
    IP.bind_header GRE, protocol: GRE::IP_PROTOCOL
    IPv6.bind_header GRE, next: GRE::IP_PROTOCOL

    GRE.bind_header IP, protocol_type: IP::ETHERTYPE
    GRE.bind_header IPv6, protocol_type: IPv6::ETHERTYPE
  end
end
