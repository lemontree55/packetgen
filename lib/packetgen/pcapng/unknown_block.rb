# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module PcapNG

    # {UnknownBlock} is used to handle unsupported blocks of a pcapng file.
    class UnknownBlock < Block

      # Minimum Iblock size
      MIN_SIZE     = 12

      # @return [:little, :big]
      attr_accessor :endian
      # @return [SHB]
      attr_accessor :section

      # @!attribute body
      #  @return [Types::String]
      define_field :body, Types::String
      # @!attribute block_len2
      #  32-bit block length
      #  @return [Integer]
      define_field :block_len2, Types::Int32

      # @option options [:little, :big] :endian set block endianness
      # @option options [Integer] :type
      # @option options [Integer] :block_len block total length
      # @option options [::String] :body
      # @option options [Integer] :block_len2 block total length
      def initialize(options={})
        super
        set_endianness(options[:endian] || :little)
        recalc_block_len
      end

      # Has this block option?
      # @return [false]
      def has_options?
        false
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

        self[:type].read io.read(4)
        self[:block_len].read io.read(4)
        self[:body].read io.read(self[:block_len].to_i - MIN_SIZE)
        self[:block_len2].read io.read(4)
        
        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Header Block'
        end

        self
      end

      # Return the object as a String
      # @return [String]
      def to_s
        pad_field :body
        recalc_block_len
        @fields.values.map(&:to_s).join
      end

    end

  end
end
