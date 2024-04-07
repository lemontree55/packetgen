# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class SCTP
      # BaseChunk class, defining SCTP chunk common fields
      #   0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |  Chunk Type   |  Chunk Flags  |         Chunk Length          |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @abstract Subclass and add more fields
      class BaseChunk < Base
        # SCTP chunk types, as per RFC9260
        TYPES = {
          'DATA' => 0,
          'INIT' => 1,
          'INIT_ACK' => 2,
          'SACK' => 3,
          'HEARTBEAT' => 4,
          'HEARTBEAT_ACK' => 5,
          'ABORT' => 6,
          'SHUTDOWN' => 7,
          'SHUTDOWN_ACK' => 8,
          'ERROR' => 9,
          'COOKIE_ECHO' => 10,
          'COOKIE_ACK' => 11,
          'ECNE' => 12,
          'CWR' => 13,
          'SHUTDOWN_COMPLETE' => 14,
        }.freeze

        # @!attribute type
        #  8-bit SCTP chunk type
        #  @return [Integer]
        define_field :type, Types::Int8Enum, enum: TYPES
        # @!attribute type
        #  8-bit SCTP chunk flags
        #  @return [Integer]
        define_field :flags, Types::Int8
        # @!attribute length
        #  16-bit SCTP chunk length
        #  @return [Integer]
        define_field :length, Types::Int16

        # Convert Chunk to its binary representation. Automatically
        # add padding
        # @return [Strung]
        def to_s
          data = super
          padlen = -(data.size % -4)
          data << ([0] * padlen).pack('C*')
        end

        # Get human-redable chunk
        # @return [String]
        def to_human
          str = +"<chunk:#{human_type}"
          flags_str = flags_to_human
          str << if flags_str.empty?
                   '>'
                 else
                   ",#{flags_to_human}>"
                 end
        end

        # @return [String,Integer]
        def human_type
          self[:type].to_human
        end

        # Compute length from value content
        # @note: chunk length includes type, flags and length fields
        def calc_length
          Base.calculate_and_set_length(self)
        end

        private

        def flags_to_human
          ''
        end
      end

      # Embed chunks for a given {SCTP} packet.
      class ArrayOfChunks < Types::Array
        set_of BaseChunk

        private

        # Get real type from Chunk type
        def real_type(opt)
          type_name = BaseChunk::TYPES.key(opt.type)
          return opt.class if type_name.nil?

          klass_name = type_name.split('_').map(&:capitalize).join << 'Chunk'
          SCTP.const_get(klass_name) || UnknownChunk
        end
      end

      # UnknownChunk, used when type cannot be decoded
      #   0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |  Chunk Type   |  Chunk Flags  |         Chunk Length          |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  \                                                               \
      #  /                          Chunk Value                          /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      class UnknownChunk < BaseChunk
        # @!attribute body
        #  SCTP chunk value
        #  @return [String]
        define_field :body, Types::String, builder: ->(h, t) { t.new(length_from: -> { h.length - 4 }) }
      end

      # Data chunk
      #   0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 0    |  Res  |I|U|B|E|            Length             |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                              TSN                              |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |      Stream Identifier S      |   Stream Sequence Number n    |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                  Payload Protocol Identifier                  |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  \                                                               \
      #  /                 User Data (seq n of Stream S)                 /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      class DataChunk < BaseChunk
        # @!attribute tsn
        #   32-bit TSN for this DATA chunk
        #   @return [Integer]
        define_field :tsn, Types::Int32
        # @!attribute stream_id
        #  16-bit stream identifier
        #  @return [Integer]
        define_field :stream_id, Types::Int16
        # @!attribute stream_sn
        #  16-bit stream sequence number
        #  @return [Integer]
        define_field :stream_sn, Types::Int16
        # @!attribute ppid
        #  32-bit payload protocol identifier
        #  @return [Integer]
        define_field :ppid, Types::Int32
        # @!attribute body
        #  SCTP chunk value
        #  @return [String]
        define_field :body, Types::String, builder: ->(h, t) { t.new(length_from: -> { h.length - 4 }) }

        # @!attribute flag_i
        #  IMMEDIATE flag
        #  @return [Boolean]
        # @!attribute flag_u
        #  UNORDERED flag
        #  @return [Boolean]
        # @!attribute flag_b
        #  BEGINNING fragment flag
        #  @return [Boolean]
        # @!attribute flag_e
        #  ENDING fragment flag
        #  @return [Boolean]
        define_bit_fields_on :flags, :flag_res, 4, :flag_i, :flag_u, :flag_b, :flag_e
      end
    end
  end
end
