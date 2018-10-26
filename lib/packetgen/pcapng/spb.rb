# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module PcapNG
    # {SPB} represents a Section Simple Packet Block (SPB) of a pcapng file.
    #
    # == Pcapng::SPB Definition
    #   Int32   :type           Default: 0x00000003
    #   Int32   :block_len
    #   Int32   :orig_len
    #   String  :data
    #   Int32   :block_len2
    # @author Sylvain Daubert
    class SPB < Block
      # Minimum SPB size
      MIN_SIZE = 4 * 4

      # @return [:little, :big]
      attr_accessor :endian
      # @return [IPB]
      attr_accessor :interface

      # @!attribute orig_len
      #  32-bit original length
      #  @return [Integer]
      define_field_before :block_len2, :orig_len, Types::Int32, default: 0
      # @!attribute data
      #  @return [Types::String]
      define_field_before :block_len2, :data, Types::String

      # @param [Hash] options
      # @option options [:little, :big] :endian set block endianness
      # @option options [Integer] :type
      # @option options [Integer] :block_len block total length
      # @option options [Integer] :orig_len actual length of the packet when it was
      #                                     transmitted on the network
      # @option options [::String] :data
      # @option options [::String] :options
      # @option options [Integer] :block_len2 block total length
      def initialize(options={})
        super
        set_endianness(options[:endian] || :little)
        recalc_block_len
        self.type = options[:type] || PcapNG::SPB_TYPE.to_i
      end

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
        io = if str_or_io.respond_to? :read
               str_or_io
             else
               StringIO.new(force_binary(str_or_io.to_s))
             end
        return self if io.eof?

        self[:type].read io.read(4)
        self[:block_len].read io.read(4)
        self[:orig_len].read io.read(4)
        # Take care of IDB snaplen
        # CAUTION: snaplen == 0 -> no capture limit
        data_len = if interface && (interface.snaplen.to_i > 0)
                     [self[:orig_len].to_i, interface.snaplen.to_i].min
                   else
                     self[:orig_len].to_i
                   end
        data_pad_len = (4 - (data_len % 4)) % 4
        self[:data].read io.read(data_len)
        io.read data_pad_len
        self[:block_len2].read io.read(4)

        check_len_coherency
        self.type ||= PcapNG::IDB_TYPE.to_i
        self
      end

      # Return the object as a String
      # @return [String]
      def to_s
        pad_field :data
        recalc_block_len
        super
      end
    end
  end
end
