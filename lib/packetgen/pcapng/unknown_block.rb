# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module PcapNG
    # {UnknownBlock} is used to handle unsupported blocks of a pcapng file.
    # @author Sylvain Daubert
    class UnknownBlock < Block
      # Minimum Iblock size
      MIN_SIZE = 12

      # @return [:little, :big]
      attr_accessor :endian
      # @return [SHB]
      attr_accessor :section

      # @!attribute body
      #  @return [BinStruct::String]
      define_attr_before :block_len2, :body, BinStruct::String

      # Has this block options?
      # @return [false]
      # @since 2.7.0
      def options?
        false
      end

      # Reads a String or a IO to populate the object
      # @param [::String,IO] str_or_io
      # @return [self]
      def read(str_or_io)
        io = to_io(str_or_io)
        return self if io.eof?

        self[:type].read(io.read(4))
        self[:block_len].read(io.read(4))
        self[:body].read(io.read(self[:block_len].to_i - MIN_SIZE))
        read_blocklen2_and_check(io)

        self
      end

      # Return the object as a String
      # @return [String]
      def to_s
        pad_field(:body)
        recalc_block_len
        super
      end
    end
  end
end
