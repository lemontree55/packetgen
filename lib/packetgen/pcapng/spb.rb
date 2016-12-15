# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

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
    class SPB < Struct.new(:type, :block_len, :orig_len, :data, :block_len2)
      include StructFu
      include Block

      # @return [:little, :big]
      attr_accessor :endian
      # @return [IPB]
      attr_accessor :interface

      # Minimum SPB size
      MIN_SIZE     = 4*4

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
        @endian = set_endianness(options[:endian] || :little)
        init_fields(options)
        super(options[:type], options[:block_len], options[:orig_len], options[:data],
              options[:block_len2])
      end

      # Used by {#initialize} to set the initial fields
      # @param [Hash] options
      # @see #initialize possible options
      # @return [Hash] return +options+
      def init_fields(options={})
        options[:type]  = @int32.new(options[:type] || PcapNG::SPB_TYPE.to_i)
        options[:block_len] = @int32.new(options[:block_len] || MIN_SIZE)
        options[:orig_len] = @int32.new(options[:orig_len] || 0)
        options[:data] = StructFu::String.new(options[:data] || '')
        options[:block_len2] = @int32.new(options[:block_len2] || MIN_SIZE)
        options
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
        self[:orig_len].read io.read(4)
        # Take care of IDB snaplen
        # CAUTION: snaplen == 0 -> no capture limit
        if interface and interface.snaplen.to_i > 0
          data_len = [self[:orig_len].to_i, interface.snaplen.to_i].min
        else
          data_len = self[:orig_len].to_i
        end
        data_pad_len = (4 - (data_len % 4)) % 4
        self[:data].read io.read(data_len)
        io.read data_pad_len
        self[:block_len2].read io.read(4)

        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Simple Packet Block'
        end

        self
      end

      # Return the object as a String
      # @return [String]
      def to_s
        pad_field :data
        recalc_block_len
        to_a.map(&:to_s).join
      end

    end

  end
end
