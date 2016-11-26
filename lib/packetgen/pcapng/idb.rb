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
    class IDB < Struct.new(:type, :block_len, :link_type, :reserved,
                           :snaplen, :options, :block_len2)
      include StructFu
      include Block

      # @return [:little, :big]
      attr_accessor :endian
      # @return [SHB]
      attr_accessor :section
      # @return [Array<EPB,SPB>]
      attr_accessor :packets

      # Minimum IDB size
      MIN_SIZE     = 5*4

      # Option code for if_tsresol option
      OPTION_IF_TSRESOL = 9

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
        @endian = set_endianness(options[:endian] || :little)
        @packets = []
        @options_decoded = false
        init_fields(options)
        super(options[:type], options[:block_len], options[:link_type], options[:reserved],
              options[:snaplen], options[:options], options[:block_len2])
      end

      # Used by {#initialize} to set the initial fields
      # @see #initialize possible options
      # @param [Hash] options
      # @return [Hash] return +options+
      def init_fields(options={})
        options[:type]  = @int32.new(options[:type] || PcapNG::IDB_TYPE.to_i)
        options[:block_len] = @int32.new(options[:block_len] || MIN_SIZE)
        options[:link_type] = @int16.new(options[:link_type] || 1)
        options[:reserved] = @int16.new(options[:reserved] || 0)
        options[:snaplen] = @int32.new(options[:snaplen] || 0)
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

        self[:type].read io.read(4)
        self[:block_len].read io.read(4)
        self[:link_type].read io.read(2)
        self[:reserved].read io.read(2)
        self[:snaplen].read io.read(4)
        self[:options].read io.read(self[:block_len].to_i - MIN_SIZE)
        self[:block_len2].read io.read(4)

        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Interface Description Block'
        end
      
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
        to_a.map(&:to_s).join + @packets.map(&:to_s).join
      end

    end

  end
end
