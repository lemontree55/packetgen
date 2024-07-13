# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.
require 'digest/crc32c'

module PacketGen
  module Header
    # SCTP header ({https://tools.ietf.org/html/rfc9260 RFC 9260})
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |      Source Port Number       |    Destination Port Number    |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                       Verification Tag                        |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                           Checksum                            |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                           Chunk #1                            |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                              ...                              |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                           Chunk #n                            |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # @author Sylvain Daubert
    # @since 3.4.0
    class SCTP < Base; end
  end
end

require_relative 'sctp/chunk'
require_relative 'udp'

module PacketGen
  module Header
    class SCTP < Base
      # IP protocol number for SCTP
      IP_PROTOCOL = 132
      # Port number for SCTP over TCP (RFC 6951)
      UDP_PORT = 9899

      # @!attribute sport
      #  16-bit TCP source port
      #  @return [Integer]
      define_field :sport, Types::Int16
      # @!attribute dport
      #  16-bit TCP destination port
      #  @return [Integer]
      define_field :dport, Types::Int16
      # @!attribute verification_tag
      #  32-bit verification tag
      #  @return [Integer]
      define_field :verification_tag, Types::Int32
      # @!attribute checksum
      #  32-bit TCP checksum
      #  @return [Integer]
      define_field :checksum, Types::Int32le
      # @!attribute chunks
      #  List of chunks this packet transports
      #  @return [ArrayOfChunk]
      define_field :chunks, ArrayOfChunk

      # Compute SCTP checksum
      def calc_checksum
        self.checksum = 0
        crc32c = Digest::CRC32c.new
        crc32c << to_s
        self.checksum = crc32c.checksum
      end

      # Compute SCTP chunks length
      def calc_length
        self.chunks.each(&:calc_length)
      end

      # @return [String]
      def inspect
        super do |attr|
          next unless attr == :chunks

          chunks.map(&:inspect).join
        end
      end
    end

    self.add_class SCTP

    IP.bind SCTP, protocol: SCTP::IP_PROTOCOL
    IPv6.bind SCTP, next: SCTP::IP_PROTOCOL
    UDP.bind SCTP, dport: SCTP::UDP_PORT
  end
end
