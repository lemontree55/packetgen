# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv2

      # This class handles {OSPFv2 OSPFv2} LSA header. A LSA header has the
      # following format:
      #   0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |            LS age             |    Options    |    LS type    |
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
      # LSA headers are used as-is in {DbDescription} payload. But this class
      # is also a base class for different LSA class, as {LSARouter}.
      # @author Sylvain Daubert
      class LSAHeader < Types::Fields
        # LSA Types
        TYPES = {
          'Router'       => 1,
          'Network'      => 2,
          'Summary-IP'   => 3,
          'Summary-ABSR' => 4,
          'AS-External'  => 5
        }

        # @!attribute age
        #  The time in seconds since the LSA was originated.
        #  @return [Integer]
        define_field :age, Types::Int16
        # @!macro define_options
        OSPFv2.define_options(self)
        # @!attribute type
        #  The type of the LSA.
        #  @return [Integer]
        define_field :type, Types::Int8Enum, enum: TYPES
        # @!attribute link_state_id
        #  This field identifies the portion of the internet environment
        #  that is being described by the LSA.
        #  @return [String]
        define_field :link_state_id, IP::Addr
        # @!attribute advertising_router
        #  The Router ID of the router that originated the LSA.
        #  @return [String]
        define_field :advertising_router, IP::Addr
        # @!attribute sequence_number
        #  @return [Integer]
        define_field :sequence_number, Types::Int32
        alias seqnum sequence_number
        alias seqnum= sequence_number=
        # @!attribute checksum
        #  The Fletcher checksum of the complete contents of the LSA,
        #  including the LSA header but excluding the LS age field.
        #  @return [Integer]
        define_field :checksum, Types::Int16
        # @!attribute length
        #  Length of the LSA, including the header.
        #  @return [Integer]
        define_field :length, Types::Int16
        
        # Compute and set Fletcher-16 checksum on LSA
        # @return [Integer]
        def calc_checksum
          self.checksum = 0

          c0 = c1 = 0
          bytes = to_s[2..-1].unpack('C*')
          bytes.each do |byte|
            c0 += byte
            c1 += c0
          end
          c0 %= 255
          c1 %= 255
          
          x = ((sz - 16 - 1) * c0 - c1) % 255
          x += 255 if x <= 0
          y = 255*2 - c0 - x
          y -= 255 if y > 255
          self.checksum = (x << 8) | y
        end

        # Compute length and set +length+ field
        # @return [Integer]
        def calc_length
          self.length = Base.calculate_and_set_length(self)
        end

        # Get human-readable type
        # @return [String]
        def human_type
          self[:type].to_human
        end

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
