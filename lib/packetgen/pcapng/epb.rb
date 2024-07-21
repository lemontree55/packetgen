# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module PcapNG
    # {EPB} represents a Enhanced Packet Block (EPB) of a pcapng file.
    #
    # == EPB Definition
    #   Int32   :type           Default: 0x00000006
    #   Int32   :block_len
    #   Int32   :interface_id
    #   Int32   :tsh (timestamp high)
    #   Int32   :tsl (timestamp low)
    #   Int32   :cap_len
    #   Int32   :orig_len
    #   String  :data
    #   String  :options
    #   Int32   :block_len2
    # @author Sylvain Daubert
    class EPB < Block
      # Minimum EPB size
      MIN_SIZE = 8 * 4

      # @return [:little, :big]
      attr_accessor :endian
      # @return [IPB]
      attr_accessor :interface

      # @!attribute interface_id
      #  32-bit interface ID
      #  @return [Integer]
      define_attr_before :block_len2, :interface_id, BinStruct::Int32, default: 0
      # @!attribute tsh
      #  high 32-bit timestamp value
      #  @return [Integer]
      define_attr_before :block_len2, :tsh, BinStruct::Int32, default: 0
      # @!attribute tsl
      #  low 32-bit imestamp value
      #  @return [Integer]
      define_attr_before :block_len2, :tsl, BinStruct::Int32, default: 0
      # @!attribute cap_len
      #  32-bit capture length
      #  @return [Integer]
      define_attr_before :block_len2, :cap_len, BinStruct::Int32, default: 0
      # @!attribute orig_len
      #  32-bit original length
      #  @return [Integer]
      define_attr_before :block_len2, :orig_len, BinStruct::Int32, default: 0
      # @!attribute data
      #  @return [BinStruct::String]
      define_attr_before :block_len2, :data, BinStruct::String
      # @!attribute options
      #  @return [BinStruct::String]
      define_attr_before :block_len2, :options, BinStruct::String

      # @param [Hash] options
      # @option options [:little, :big] :endian set block endianness
      # @option options [Integer] :type
      # @option options [Integer] :block_len block total length
      # @option options [Integer] :interface_id specifies the interface this packet
      #   comes from
      # @option options [Integer] :tsh timestamp (high nibbles)
      # @option options [Integer] :tsl timestamp (low nibbles)
      # @option options [Integer] :cap_len number of octets captured from the packet
      # @option options [Integer] :orig_len actual length of the packet when it was
      #   transmitted on the network
      # @option options [::String] :data
      # @option options [::String] :options
      # @option options [Integer] :block_len2 block total length
      def initialize(options={})
        super
        endianness(options[:endian] || :little)
        recalc_block_len
        self.type = options[:type] || PcapNG::EPB_TYPE.to_i
      end

      # Reads a String or a IO to populate the object
      # @param [::String,IO] str_or_io
      # @return [self]
      def read(str_or_io)
        io = to_io(str_or_io)
        return self if io.eof?

        %i[type block_len interface_id tsh tsl cap_len orig_len].each do |attr|
          self[attr].read io.read(self[attr].sz)
        end
        self[:data].read io.read(self.cap_len)
        read_options(io)
        read_blocklen2_and_check(io)

        self
      end

      # Return timestamp as a Time object
      # @return [Time]
      def timestamp
        Time.at((self.tsh << 32 | self.tsl) * ts_resol)
      end

      # Set timestamp from a Time object
      # @param [Time] time
      # @return [Time] time
      def timestamp=(time)
        tstamp = (time.to_r / ts_resol).to_i
        self.tsh = (tstamp & 0xffffffff00000000) >> 32
        self.tsl = tstamp & 0xffffffff
        time
      end

      # Return the object as a String
      # @return [String]
      def to_s
        pad_field :data, :options
        recalc_block_len
        super
      end

      private

      def ts_resol
        if !defined?(@interface) || @interface.nil?
          1E-6
        else
          @interface.ts_resol
        end
      end

      def read_options(io)
        data_pad_len = remove_padding(io, self.cap_len)
        options_len = self.block_len - self.cap_len - data_pad_len - MIN_SIZE
        self[:options].read io.read(options_len)
      end
    end
  end
end
