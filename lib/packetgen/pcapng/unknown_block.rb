module PacketGen
  module PcapNG

    # {UnknownBlock} is used to handle unsupported blocks of a pcapng file.
    class UnknownBlock < Struct.new(:type, :block_len, :body, :block_len2)
      include StructFu
      include Block

      # @return [:little, :big]
      attr_accessor :endian
      # @return [SHB]
      attr_accessor :section

      # Minimum Iblock size
      MIN_SIZE     = 12

      # @option options [:little, :big] :endian set block endianness
      # @option options [Integer] :type
      # @option options [Integer] :block_len block total length
      # @option options [::String] :body
      # @option options [Integer] :block_len2 block total length
      def initialize(args={})
        @endian = set_endianness(args[:endian] || :little)
        init_fields(args)
        super(args[:type], args[:block_len], args[:body], args[:block_len2])
      end

      # Used by {#initialize} to set the initial fields
      # @see #initialize possible options
      # @param [Hash] options
      # @return [Hash] return +options+
      def init_fields(args={})
        args[:type]  = @int32.new(args[:type] || 0)
        args[:block_len] = @int32.new(args[:block_len] || MIN_SIZE)
        args[:body] = StructFu::String.new(args[:body] || '')
        args[:block_len2] = @int32.new(args[:block_len2] || MIN_SIZE)
        args
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
        to_a.map(&:to_s).join
      end

    end

  end
end
