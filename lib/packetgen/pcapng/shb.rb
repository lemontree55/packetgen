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
    class SHB < Struct.new(:type, :block_len, :magic, :ver_major, :ver_minor,
                           :section_len, :options, :block_len2)
      include StructFu
      include Block

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
      MIN_SIZE     = 7*4
      # +section_len+ value for undefined length
      SECTION_LEN_UNDEFINED = 0xffffffff_ffffffff

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
        @endian = set_endianness(options[:endian] || :little)
        @interfaces = []
        @unknown_blocks = []
        init_fields(options)
        super(options[:type], options[:block_len], options[:magic], options[:ver_major],
              options[:ver_minor], options[:section_len], options[:options], options[:block_len2])
      end

      # Used by {#initialize} to set the initial fields
      # @see #initialize possible options
      # @param [Hash] options
      # @return [Hash] return +options+
      def init_fields(options={})
        options[:type]  = @int32.new(options[:type] || PcapNG::SHB_TYPE.to_i)
        options[:block_len] = @int32.new(options[:block_len] || MIN_SIZE)
        options[:magic] = @int32.new(options[:magic] || MAGIC_INT32)
        options[:ver_major] = @int16.new(options[:ver_major] || 1)
        options[:ver_minor] = @int16.new(options[:ver_minor] || 0)
        options[:section_len] = @int64.new(options[:section_len] || SECTION_LEN_UNDEFINED)
        options[:options] = StructFu::String.new(options[:options] || '')
        options[:block_len2] = @int32.new(options[:block_len2] || MIN_SIZE)
        options
      end

      # Reads a String or a IO to populate the object
      # @param [::String,IO] str_or_io
      # @return [self]
      def read(str_or_io)
        if str_or_io.respond_to? :read
          io = str_or_io
        else
          io = StringIO.new(force_binary(str_or_io.to_s))
        end
        return self if io.eof?

        type_str = io.read(4)
        unless type_str == PcapNG::SHB_TYPE.to_s
          type = type_str.unpack('H*').join
          raise InvalidFileError, "Incorrect type (#{type})for Section Header Block"
        end

        block_len_str = io.read(4)

        magic_str = io.read(4)
        case @endian
        when :little
          case magic_str
          when MAGIC_LITTLE
          when MAGIC_BIG
            force_endianness :big
          else
            raise InvalidFileError, 'Incorrect magic for Section Header Block'
          end
        when :big
          case magic_str
          when MAGIC_BIG
          when MAGIC_LITTLE
            force_endianness :little
          else
            raise InvalidFileError, 'Incorrect magic for Section Header Block'
          end
        end

        self[:type].read type_str
        self[:block_len].read block_len_str
        self[:magic].read magic_str
        self[:ver_major].read io.read(2)
        self[:ver_minor].read io.read(2)
        self[:section_len].read io.read(8)
        self[:options].read io.read(self[:block_len].to_i - MIN_SIZE)
        self[:block_len2].read io.read(4)

        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Section Header Block'
        end

        self
      end

      # Add a IDB to this section
      # @param [IDB] idb
      # @return [self]
      def <<(idb)
        @interfaces << idb
        self
      end

      # Return the object as a String
      # @return [String]
      def to_s
        body = @interfaces.map(&:to_s).join
        unless self[:section_len].to_i == SECTION_LEN_UNDEFINED
          self.section_len.value = body.size
        end
        pad_field :options
        recalc_block_len
        to_a.map(&:to_s).join + body
      end


      private

      def force_endianness(endian)
        set_endianness endian
        @endian = endian
        self[:type]  = @int32.new(self[:type].to_i)
        self[:block_len] = @int32.new(self[:block_len].to_i)
        self[:magic] = @int32.new(self[:magic].to_i)
        self[:ver_major] = @int16.new(self[:ver_major].to_i)
        self[:ver_minor] = @int16.new(self[:ver_minor].to_i)
        self[:section_len] = @int64.new(self[:section_len].to_i)
        self[:block_len2] = @int32.new(self[:block_len2].to_i)
      end

    end

  end
end
