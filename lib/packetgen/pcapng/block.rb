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
      def has_options?
        @fields.has_key?(:options) && @fields[:options].sz > 0
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
          unless @fields[field].size % 4 == 0
            @fields[field] << "\x00" * (4 - (@fields[field].size % 4))
          end
        end
      end

      private

      # Set the endianness for the various Int classes handled by self.
      # Must be called by all subclass #initialize method.
      # @param [:little, :big] e
      # @return [:little, :big] returns e
      def set_endianness(e)
        unless [:little, :big].include? e
          raise ArgumentError, "unknown endianness for #{self.class}"
        end
        @endian = e
        @fields.each { |f_, v| v.endian = e if v.is_a?(Types::Int) }
        e
      end

      def check_len_coherency
        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Block length'
        end
      end
    end
  end
end
