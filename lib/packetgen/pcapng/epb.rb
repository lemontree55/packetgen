module PacketGen
  module PcapNG

    # {EPB} represents a Enhanced Packet Block (EPB) of a pcapng file.
    #
    # == EPB Definition
    #   Int32   :type           Default: 0x00000006
    #   Int32   :block_len
    #   Int32   :interface_id
    #   Int32   :tsh (timestamp high)
    #   Int32   :tsl (timestamp low)
    #   Int32   :cap_len
    #   Int32   :orig_len
    #   String  :data
    #   String  :options
    #   Int32   :block_len2
    class EPB < Struct.new(:type, :block_len, :interface_id, :tsh, :tsl,
                           :cap_len, :orig_len, :data, :options, :block_len2)
      include StructFu
      include Block

      # @return [:little, :big]
      attr_accessor :endian
      # @return [IPB]
      attr_accessor :interface

      # Minimum EPB size
      MIN_SIZE     = 8*4

      # @param [Hash] options
      # @option options [:little, :big] :endian set block endianness
      # @option options [Integer] :type
      # @option options [Integer] :block_len block total length
      # @option options [Integer] :interface_id specifies the interface this packet
      #   comes from
      # @option options [Integer] :tsh timestamp (high nibbles)
      # @option options [Integer] :tsl timestamp (low nibbles)
      # @option options [Integer] :cap_len number of octets captured from the packet
      # @option options [Integer] :orig_len actual length of the packet when it was
      #   transmitted on the network
      # @option options [::String] :data
      # @option options [::String] :options
      # @option options [Integer] :block_len2 block total length
      def initialize(options={})
        @endian = set_endianness(options[:endian] || :little)
        init_fields(options)
        super(options[:type], options[:block_len], options[:interface_id], options[:tsh],
              options[:tsl], options[:cap_len], options[:orig_len], options[:data],
              options[:options], options[:block_len2])
      end

      # Used by {#initialize} to set the initial fields
      # @param [Hash] options
      # @see #initialize possible options
      # @return [Hash] return +options+
      def init_fields(options={})
        options[:type]  = @int32.new(options[:type] || PcapNG::EPB_TYPE.to_i)
        options[:block_len] = @int32.new(options[:block_len] || MIN_SIZE)
        options[:interface_id] = @int32.new(options[:interface_id] || 0)
        options[:tsh] = @int32.new(options[:tsh] || 0)
        options[:tsl] = @int32.new(options[:tsl] || 0)
        options[:cap_len] = @int32.new(options[:cap_len] || 0)
        options[:orig_len] = @int32.new(options[:orig_len] || 0)
        options[:data] = StructFu::String.new(options[:data] || '')
        options[:options] = StructFu::String.new(options[:options] || '')
        options[:block_len2] = @int32.new(options[:block_len2] || MIN_SIZE)
        options
      end

      # Has this block option?
      # @return [Boolean]
      def has_options?
        self[:options].size > 0
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
        self[:interface_id].read io.read(4)
        self[:tsh].read io.read(4)
        self[:tsl].read io.read(4)
        self[:cap_len].read io.read(4)
        self[:orig_len].read io.read(4)
        self[:data].read io.read(self[:cap_len].to_i)
        data_pad_len = (4 - (self[:cap_len].to_i % 4)) % 4
        io.read data_pad_len
        options_len = self[:block_len].to_i - self[:cap_len].to_i - data_pad_len
        options_len -= MIN_SIZE
        self[:options].read io.read(options_len)
        self[:block_len2].read io.read(4)

        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Extended Packet Block'
        end
      
        self
      end

      # Return timestamp as a Time object
      # @return [Time]
      def timestamp
        Time.at((self[:tsh].to_i << 32 | self[:tsl].to_i) * ts_resol)
      end

      # Return the object as a String
      # @return [String]
      def to_s
        pad_field :data, :options
        recalc_block_len
        to_a.map(&:to_s).join
      end


      private

      def ts_resol
        if @interface.nil?
          1E-6
        else
          @interface.ts_resol
        end
      end

    end

  end
end
