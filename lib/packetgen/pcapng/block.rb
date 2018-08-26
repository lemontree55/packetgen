# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

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
      # @since 2.6.1
      def options?
        @fields.key?(:options) && @fields[:options].sz > 0
      end

      # @deprecated Use {#options?} instead.
      # @return [Boolean]
      def has_options?
        Deprecation.deprecated(self.class, __method__, 'options?')
        options?
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
          unless (@fields[field].size % 4).zero?
            @fields[field] << "\x00" * (4 - (@fields[field].size % 4))
          end
        end
      end

      private

      # Set the endianness for the various Int classes handled by self.
      # Must be called by all subclass #initialize method.
      # @param [:little, :big] endian
      # @return [:little, :big] returns endian
      def set_endianness(endian)
        unless %i[little big].include? endian
          raise ArgumentError, "unknown endianness for #{self.class}"
        end
        @endian = endian
        @fields.each { |_f, v| v.endian = endian if v.is_a?(Types::Int) }
        endian
      end

      def check_len_coherency
        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Block length'
        end
      end
    end
  end
end
