# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3
      # This class handles {OSPFv3 OSPFv3} LSA header. A LSA header has the
      # following format:
      #   0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |           LS Age              |           LS Type             |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                        Link State ID                          |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                     Advertising Router                        |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                     LS sequence number                        |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |         LS checksum           |             length            |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #
      # == About LSA headers
      # LSA headers are used as-is in {DbDescription} and {LSAck} payloads.
      # But this class is also a base class for different LSA class, as {LSARouter}.
      # @author Sylvain Daubert
      class LSAHeader < BinStruct::Struct
        include BinStruct::Structable

        # LSA known types
        TYPES = {
          'Router' => 0x2001,
          'Network' => 0x2002,
          'Inter-Area-Prefix' => 0x2003,
          'Inter-Area-Router' => 0x2004,
          'AS-External' => 0x4005,
          'NSSA' => 0x2007,
          'Link' => 0x0008,
          'Intra-Area-Prefix' => 0x2009
        }.freeze

        # @!attribute age
        #  The time in seconds since the LSA was originated.
        #  @return [Integer]
        define_attr :age, BinStruct::Int16
        # @!attribute type
        #  The type of the LSA.
        #  @return [Integer]
        define_attr :type, BinStruct::Int16Enum, enum: TYPES
        # @!attribute link_state_id
        #  This field identifies the portion of the internet environment
        #  that is being described by the LSA.
        #  @return [String]
        define_attr :link_state_id, IP::Addr
        # @!attribute advertising_router
        #  The Router ID of the router that originated the LSA.
        #  @return [String]
        define_attr :advertising_router, IP::Addr
        # @!attribute sequence_number
        #  @return [Integer]
        define_attr :sequence_number, BinStruct::Int32
        alias seqnum sequence_number
        alias seqnum= sequence_number=
        # @!attribute checksum
        #  The Fletcher checksum of the complete contents of the LSA,
        #  including the LSA header but excluding the LS age field.
        #  @return [Integer]
        define_attr :checksum, BinStruct::Int16
        # @!attribute length
        #  Length of the LSA, including the header.
        #  @return [Integer]
        define_attr :length, BinStruct::Int16

        # Compute and set Fletcher-16 {#checksum} on LSA
        # @return [Integer]
        def calc_checksum
          c0 = c1 = 0
          to_s[2..].unpack('C*').each do |byte|
            c0 += byte
            c1 += c0
          end
          c0 %= 255
          c1 %= 255

          x = ((sz - 17) * c0 - c1) % 255
          x += 255 if x <= 0
          y = 255 * 2 - c0 - x
          y -= 255 if y > 255
          self.checksum = (x << 8) | y
        end

        # Compute length and set {#length} field
        # @return [Integer]
        def calc_length
          self.length = Base.calculate_and_set_length(self)
        end

        # Get human-readable type
        # @return [String]
        def human_type
          self[:type].to_human
        end

        # Get human-readable description
        # @return [String]
        def to_human
          "LSA<#{human_type},#{link_state_id},#{advertising_router}>"
        end

        # Extract header from current LSA
        # @return [LSAHeader]
        def to_lsa_header
          LSAHeader.new(self.to_h)
        end
      end
    end
  end
end
