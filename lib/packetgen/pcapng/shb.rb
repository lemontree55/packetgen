# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module PcapNG
    # {SHB} represents a Section Header Block (SHB) of a pcapng file.
    #
    # == SHB Definition
    #   Int32   :type           Default: 0x0A0D0D0A
    #   Int32   :block_len
    #   Int32   :magic          Default: 0x1A2B3C4D  # :big is 0x4D3C2C1A
    #   Int16   :ver_major      Default: 1
    #   Int16   :ver_minor      Default: 0
    #   Int64   :section_len
    #   String  :options        Default: ''
    #   Int32   :block_len2
    # @author Sylvain Daubert
    class SHB < Block
      # @return [:little, :big]
      attr_accessor :endian
      # Get interfaces for this section
      # @return [Array<IDB>]
      attr_reader :interfaces
      # Get unsupported blocks given in pcapng file as raw data
      # @return [Array<UnknownBlock>]
      attr_reader :unknown_blocks

      # Magic value to retrieve SHB
      MAGIC_INT32  = 0x1A2B3C4D
      # Magic value (little endian version)
      MAGIC_LITTLE = [MAGIC_INT32].pack('V')
      # Magic value (big endian version)
      MAGIC_BIG    = [MAGIC_INT32].pack('N')

      # Minimum SHB size
      MIN_SIZE = 7 * 4
      # +section_len+ value for undefined length
      SECTION_LEN_UNDEFINED = 0xffffffff_ffffffff

      # @!attribute magic
      #  32-bit magic number
      #  @return [Integer]
      define_field_before :block_len2, :magic, Types::Int32, default: MAGIC_INT32
      # @!attribute ver_major
      #  16-bit major version number
      #  @return [Integer]
      define_field_before :block_len2, :ver_major, Types::Int16, default: 1
      # @!attribute ver_major
      #  16-bit minor version number
      #  @return [Integer]
      define_field_before :block_len2, :ver_minor, Types::Int16, default: 0
      # @!attribute section_len
      #  64-bit section length
      #  @return [Integer]
      define_field_before :block_len2, :section_len, Types::Int64,
                          default: SECTION_LEN_UNDEFINED
      # @!attribute options
      #  @return [Types::String]
      define_field_before :block_len2, :options, Types::String

      # @param [Hash] options
      # @option options [:little, :big] :endian set block endianness
      # @option options [Integer] :type
      # @option options [Integer] :block_len block total length
      # @option options [Integer] :magic magic number to distinguish little endian
      #                                  sessions and big endian ones
      # @option options [Integer] :ver_major number of the current major version of
      #                                      the format
      # @option options [Integer] :ver_minor number of the current minor version of
      #                                      the format
      # @option options [Integer] :section_len length of following section, excluding
      #                                        he SHB itself
      # @option options [::String] :options
      # @option options [Integer] :block_len2 block total length
      def initialize(options={})
        super
        @interfaces = []
        @unknown_blocks = []
        endianness(options[:endian] || :little)
        recalc_block_len
        self.type = options[:type] || PcapNG::SHB_TYPE.to_i
      end

      # Reads a String or a IO to populate the object
      # @param [::String,IO] str_or_io
      # @return [self]
      def read(str_or_io)
        io = to_io(str_or_io)
        return self if io.eof?

        self[:type].read check_shb(io)
        %i[block_len magic ver_major ver_minor section_len].each do |attr|
          self[attr].read io.read(self[attr].sz)
        end
        handle_magic_and_check(self[:magic].to_s)

        read_options(io)
        read_blocklen2_and_check(io)

        self
      end

      # Add a IDB to this section
      # @param [IDB] idb
      # @return [self]
      def <<(idb)
        @interfaces << idb
        idb.section = self
        self
      end

      # Return the object as a String
      # @return [String]
      def to_s
        body = @interfaces.map(&:to_s).join
        self.section_len = body.size unless self.section_len == SECTION_LEN_UNDEFINED

        pad_field :options
        recalc_block_len
        super + body
      end

      def add_unknown_block(block)
        self.unknown_blocks << block
        block.section = self
      end

      private

      def force_endianness(endian)
        @endian = endian
        %i[type block_len magic block_len2].each do |attr|
          self[attr] = Types::Int32.new(0, endian).read(self[attr].to_s)
        end
        %i[ver_major ver_minor].each do |attr|
          self[attr] = Types::Int16.new(0, endian).read(self[attr].to_s)
        end
        self[:section_len] = Types::Int64.new(0, endian).read(self[:section_len].to_s)
      end

      # Check io contains a SHB
      # @param [IO] io
      # @return [String] type string
      def check_shb(io)
        type_str = io.read(4)
        return type_str if type_str == PcapNG::SHB_TYPE.to_s

        type = type_str.unpack('H*').join
        raise InvalidFileError, "Incorrect type (#{type})for Section Header Block"
      end

      def handle_magic_and_check(magic_str)
        case magic_str
        when MAGIC_LITTLE
          force_endianness :little if endian == :big
        when MAGIC_BIG
          force_endianness :big if endian == :little
        else
          raise InvalidFileError, 'Incorrect magic for Section Header Block'
        end
      end

      def read_options(io)
        self[:options].read io.read(self.block_len - MIN_SIZE)
      end
    end
  end
end
