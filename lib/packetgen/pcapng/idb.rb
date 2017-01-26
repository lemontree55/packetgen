# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module PcapNG

    # {IDB} represents a Interface Description Block (IDB) of a pcapng file.
    #
    # == IDB Definition
    #   Int32   :type           Default: 0x00000001
    #   Int32   :block_len
    #   Int16   :link_type      Default: 1
    #   Int16   :reserved       Default: 0
    #   Int64   :snaplen        Default: 0 (no limit)
    #   String  :options
    #   Int32   :block_len2
    class IDB < Block

      # Minimum IDB size
      MIN_SIZE     = 5*4

      # Option code for if_tsresol option
      OPTION_IF_TSRESOL = 9

      # @return [:little, :big]
      attr_accessor :endian
      # @return [SHB]
      attr_accessor :section
      # @return [Array<EPB,SPB>]
      attr_accessor :packets

      # @!attribute link_type
      #  16-bit link type
      #  @return [Integer]
      define_field_before :block_len2, :link_type, Types::Int16, default: 1
      # @!attribute reserved
      #  16-bit reserved field
      #  @return [Integer]
      define_field_before :block_len2, :reserved, Types::Int16, default: 0
      # @!attribute snaplen
      #  32-bit snap length
      #  @return [Integer]
      define_field_before :block_len2, :snaplen, Types::Int32, default: 0
      # @!attribute options
      #  @return [Types::String]
      define_field_before :block_len2, :options, Types::String

      # @param [Hash] options
      # @option options [:little, :big] :endian set block endianness
      # @option options [Integer] :type
      # @option options [Integer] :block_len block total length
      # @option options [Integer] :link_type
      # @option options [Integer] :reserved
      # @option options [Integer] :snaplen maximum number of octets captured from
      #                                    each packet
      # @option options [::String] :options
      # @option options [Integer] :block_len2 block total length
      def initialize(options={})
        super
        set_endianness(options[:endian] || :little)
        @packets = []
        @options_decoded = false
        recalc_block_len
        self.type = options[:type] || PcapNG::IDB_TYPE.to_i
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
        self[:link_type].read io.read(2)
        self[:reserved].read io.read(2)
        self[:snaplen].read io.read(4)
        self[:options].read io.read(self[:block_len].to_i - MIN_SIZE)
        self[:block_len2].read io.read(4)

        check_len_coherency
        self
      end
      
      # Add a xPB to this section
      # @param [EPB,SPB] xpb
      # @return [self]
      def <<(xpb)
        @packets << xpb
        self
      end

      # Give timestamp resolution for this interface
      # @param [Boolean] force if +true+, force decoding even if already done
      # @return [Float]
      def ts_resol(force: false)
        if @options_decoded and not force
          @ts_resol
        else
          packstr = (@endian == :little) ? 'v' : 'n'
          idx = 0
          options = self[:options]
          opt_code = opt_len = 0

          while idx < options.length do
            opt_code, opt_len = options[idx, 4].unpack("#{packstr}2")
            if opt_code == OPTION_IF_TSRESOL and opt_len == 1
              tsresol = options[idx+4, 1].unpack('C').first
              if tsresol & 0x80 == 0
                @ts_resol = 10 ** -tsresol
              else
                @ts_resol = 2 ** -(tsresol & 0x7f)
              end

              @options_decoded = true
              return @ts_resol
            else
              idx += 4 + opt_len
            end
          end

          @options_decoded = true
          @ts_resol = 1E-6  # default value
        end
      end

      # Return the object as a String
      # @return [String]
      def to_s
        pad_field :options
        recalc_block_len
        fields.map { |f| @fields[f].to_s }.join << @packets.map(&:to_s).join
      end

    end

  end
end
