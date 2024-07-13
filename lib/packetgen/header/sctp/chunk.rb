# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require_relative 'padded32'

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
      # @author Sylvain Daubert
      class BaseChunk < Base
        include Padded32

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

        # Get human-redable chunk
        # @return [::String]
        def to_human
          str = +"<chunk:#{human_type}"
          flags_str = flags_to_human
          str << ",flags:#{flags_str}" unless flags_str.empty?
          str << '>'
        end

        # @return [::String,Integer]
        def human_type
          self[:type].to_human
        end

        # Calculate and set chunk length
        # @todo do not count last parameter padding
        # @return [Integer]
        def calc_length
          self.length = to_s(no_padding: true).size
        end

        private

        def flags_to_human
          ''
        end
      end
    end
  end
end

require_relative 'parameter'
require_relative 'error'

module PacketGen
  module Header
    class SCTP
      # Embed chunks for a given {SCTP} packet.
      # @author Sylvain Daubert
      class ArrayOfChunk < Types::Array
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
      # @author Sylvain Daubert
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
      # @author Sylvain Daubert
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

        private

        def flags_to_human
          flags = +'....'
          flags[0] = 'i' if flag_i?
          flags[1] = 'u' if flag_u?
          flags[2] = 'b' if flag_b?
          flags[3] = 'e' if flag_e?
          flags
        end
      end

      # Init Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 1    |  Chunk Flags  |      Chunk Length             |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                         Initiate Tag                          |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |          Advertised Receiver Window Credit (a_rwnd)           |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |  Number of Outbound Streams   |   Number of Inbound Streams   |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                          Initial TSN                          |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  \                                                               \
      #  /              Optional/Variable-Length Parameters              /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class InitChunk < BaseChunk
        # @!attribute initiate_tag
        #   32-bit Initiate Tag
        #   @return [Integer]
        define_field :initiate_tag, Types::Int32
        # @!attribute a_wrnd
        #   32-bit Advertised Receiver Window Credit (a_rwnd)
        #   @return [Integer]
        define_field :a_rwnd, Types::Int32
        # @!attribute nos
        #   16-bit Number of Outbound Streams
        #   @return [Integer]
        define_field :nos, Types::Int16
        # @!attribute nis
        #   16-bit Number of Inbound Streams
        #   @return [Integer]
        define_field :nis, Types::Int16
        # @!attribute initial_tsn
        #   32-bit Initial TSN
        #   @return [Integer]
        define_field :initial_tsn, Types::Int32
        # @!attribute parameters
        #  List of parameters
        #  @return [ArrayOfParameter]
        define_field :parameters, ArrayOfParameter

        def initialize(options={})
          options[:type] = BaseChunk::TYPES['INIT'] unless options.key?(:type)
          super
        end

        # Calculate lengths, including parameters ones.
        # @return [void]
        def calc_length
          parameters.each(&:calc_length)
          super
        end

        # @return [::String]
        def to_human
          str = +"<chunk:#{human_type}"
          flags_str = flags_to_human
          str << ",flags:#{flags_str}" unless flags_str.empty?
          str << ",param:#{parameters.map(&:to_human).join(',')}" unless parameters.empty?
          str << '>'
        end
      end

      # InitAck Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 1    |  Chunk Flags  |      Chunk Length             |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                         Initiate Tag                          |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |          Advertised Receiver Window Credit (a_rwnd)           |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |  Number of Outbound Streams   |   Number of Inbound Streams   |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                          Initial TSN                          |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  \                                                               \
      #  /              Optional/Variable-Length Parameters              /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class InitAckChunk < InitChunk
        def initialize(options={})
          options[:type] = BaseChunk::TYPES['INIT_ACK'] unless options.key?(:type)
          super
        end
      end

      # Selective Acknowledge Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 3    |  Chunk Flags  |         Chunk Length          |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                      Cumulative TSN Ack                       |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |          Advertised Receiver Window Credit (a_rwnd)           |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  | Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = M |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |    Gap Ack Block #1 Start     |     Gap Ack Block #1 End      |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  /                                                               /
      #  \                              ...                              \
      #  /                                                               /
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |    Gap Ack Block #N Start     |     Gap Ack Block #N End      |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                        Duplicate TSN 1                        |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  /                                                               /
      #  \                              ...                              \
      #  /                                                               /
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                        Duplicate TSN M                        |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class SackChunk < BaseChunk
        # @!attribute ctsn_ack
        #   32-bit Cumulative TSN Ack
        #   @return [Integer]
        define_field :ctsn_ack, Types::Int32
        # @!attribute a_rwnd
        #   32-bit Advertised Receiver Window Credit
        #   @return [Integer]
        define_field :a_rwnd, Types::Int32
        # @!attribute num_gap
        #   16-bit Number of Gap Ack Blocks
        #   @return [Integer]
        define_field :num_gap, Types::Int32
        # @!attribute num_dup_tsn
        #   16-bit Number of Duplicate TSNs
        #   @return [Integer]
        define_field :num_dup_tsn, Types::Int32
        # @!attribute gaps
        #   Array of 32-bit Integers, encoding boudaries of a Gap Ack Block.
        #   16 most significant bits encode block start. 16 least significant bits encode block end.
        #   @return [Types::ArrayOfInt32]
        define_field :gaps, Types::ArrayOfInt32
        # @!attribute dup_tsns
        #   Array of 32-bit Duplicate TSNs.
        #   @return [Types::ArrayOfInt32]
        define_field :dup_tsns, Types::ArrayOfInt32

        def initialize(options={})
          options[:type] = BaseChunk::TYPES['SACK'] unless options.key?(:type)
          super
        end
      end

      # Heartbeat Request Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 4    |  Chunk Flags  |       Heartbeat Length        |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  \                                                               \
      #  /          Heartbeat Information TLV (Variable-Length)          /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class HeartbeatChunk < BaseChunk
        # @!attribute info
        #   Array of Heartbeat information TLV.
        #   @return [Types::ArrayOfInt32]
        define_field :info, HearbeatInfoParameter

        def initialize(options={})
          options[:type] = BaseChunk::TYPES['HEARTBEAT'] unless options.key?(:type)
          super
        end
      end

      # Heartbeat Acknoledgement Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 4    |  Chunk Flags  |       Heartbeat Length        |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  \                                                               \
      #  /          Heartbeat Information TLV (Variable-Length)          /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class HeartbeatAckChunk < HeartbeatChunk
        def initialize(options={})
          options[:type] = BaseChunk::TYPES['HEARTBEAT_ACK'] unless options.key?(:type)
          super
        end
      end

      # Operation Error Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 9    |  Chunk Flags  |            Length             |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  \                                                               \
      #  /                   zero or more Error Causes                   /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class ErrorChunk < BaseChunk
        # @!attribute error_causes
        #  @return [ArrayofError]
        define_field :error_causes, ArrayOfError

        def initialize(options={})
          options[:type] = BaseChunk::TYPES['ERROR'] unless options.key?(:type)
          super
        end

        # Calculate lengths, including parameters ones.
        # @return [void]
        def calc_length
          error_causes.each(&:calc_length)
          super
        end

        # @return [::String]
        def to_human
          str = +"<chunk:#{human_type}"
          flags_str = flags_to_human
          str << ",flags:#{flags_str}" unless flags_str.empty?
          str << ",causes:#{error_causes.map(&:to_human).join(',')}" unless error_causes.empty?
          str << '>'
        end
      end

      # Abort Association Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 6    |  Reserved   |T|            Length             |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  \                                                               \
      #  /                   zero or more Error Causes                   /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class AbortChunk < ErrorChunk
        # @!attribute flag_t
        #  @return [Boolean]
        define_bit_fields_on :flags, :flag_res, 7, :flag_t

        def initialize(options={})
          options[:type] = BaseChunk::TYPES['ABORT'] unless options.key?(:type)
          super
        end

        private

        def flags_to_human
          flag_t? ? 't' : '.'
        end
      end

      # Shutdown association Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 7    |  Chunk Flags  |          Length = 8           |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |                      Cumulative TSN Ack                       |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class ShutdownChunk < BaseChunk
        # @!attribute cstn_ack
        #  32-bit cumulative TSN ack
        #  @return [Integer]
        define_field :ctsn_ack, Types::Int32

        def initialize(options={})
          options[:type] = BaseChunk::TYPES['SHUTDOWN'] unless options.key?(:type)
          options[:length] = 8 unless options.key?(:length)
          super
        end
      end

      # Shutdown acknowledgement Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 8    |  Chunk Flags  |          Length = 4           |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class ShutdownAckChunk < BaseChunk
        def initialize(options={})
          options[:type] = BaseChunk::TYPES['SHUTDOWN_ACK'] unless options.key?(:type)
          options[:length] = 4 unless options.key?(:length)
          super
        end
      end

      # Cookie Echo Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 10   |  Chunk Flags  |            Length             |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  /                            Cookie                             /
      #  \                                                               \
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class CookieEchoChunk < BaseChunk
        # @!attribute cookie
        #  @return [String]
        define_field :cookie, Types::String

        def initialize(options={})
          options[:type] = BaseChunk::TYPES['COOKIE_ECHO'] unless options.key?(:type)
          super
        end
      end

      # Cookie Acknownledgement Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 11   |  Chunk Flags  |            Length             |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class CookieAckChunk < BaseChunk
        def initialize(options={})
          options[:type] = BaseChunk::TYPES['COOKIE_ACK'] unless options.key?(:type)
          options[:length] = 4 unless options.key?(:length)
          super
        end
      end

      # Shutdown Complete Chunk
      #         0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |   Type = 14   |  Reserved   |T|          Length = 4           |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class ShutdownCompleteChunk < BaseChunk
        # @!attribute flag_t
        #  @return [Boolean]
        define_bit_fields_on :flags, :flag_res, 7, :flag_t

        def initialize(options={})
          options[:type] = BaseChunk::TYPES['SHUTDOWN_COMPLETE'] unless options.key?(:type)
          options[:length] = 4 unless options.key?(:length)
          super
        end
      end
    end
  end
end
