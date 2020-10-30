# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module PcapNG
    # @abstract Base class for all block types
    # @author Sylvain Daubert
    class Block < Types::Fields
      # @return [:little, :big]
      attr_accessor :endian

      # @!attribute type
      #  32-bit block type
      #  @return [Integer]
      define_field :type, Types::Int32
      # @!attribute block_len
      #  32-bit block length
      #  @return [Integer]
      define_field :block_len, Types::Int32
      # @!attribute block_len
      #  32-bit block length
      #  @return [Integer]
      define_field :block_len2, Types::Int32

      def initialize(options={})
        super
      end

      # Has this block option?
      # @return [Boolean]
      # @since 2.7.0
      def options?
        @fields.key?(:options) && @fields[:options].sz.positive?
      end

      # Calculate block length and update :block_len and block_len2 fields
      # @return [void]
      def recalc_block_len
        len = fields.map { |f| @fields[f].to_s }.join.size
        self.block_len = self.block_len2 = len
      end

      # Pad given field to 32 bit boundary, if needed
      # @param [Array<Symbol>] fields block fields to pad
      # @return [void]
      def pad_field(*fields)
        fields.each do |field|
          obj = @fields[field]
          pad_size = (obj.sz % 4).zero? ? 0 : (4 - (obj.sz % 4))
          obj << "\x00" * pad_size
        end
      end

      private

      # Set the endianness for the various Int classes handled by self.
      # Must be called by all subclass #initialize method.
      # @param [:little, :big] endian
      # @return [:little, :big] returns endian
      def endianness(endian)
        raise ArgumentError, "unknown endianness for #{self.class}" unless %i[little big].include?(endian)

        @endian = endian
        @fields.each { |_f, v| v.endian = endian if v.is_a?(Types::Int) }
        endian
      end

      def check_len_coherency
        raise InvalidFileError, 'Incoherency in Block length' unless self.block_len == self.block_len2
      end

      def to_io(str_or_io)
        return str_or_io if str_or_io.respond_to? :read

        StringIO.new(force_binary(str_or_io.to_s))
      end

      def remove_padding(io, data_len)
        data_pad_len = (4 - (data_len % 4)) % 4
        io.read data_pad_len
        data_pad_len
      end

      def read_blocklen2_and_check(io)
        self[:block_len2].read io.read(4)
        check_len_coherency
      end
    end
  end
end
