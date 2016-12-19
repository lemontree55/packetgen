module PacketGen
  module Header

    # A ESP header consists of:
    # * a Security Parameters Index (#{spi}, {Int32} type),
    # * a Sequence Number ({#sn}, +Int32+ type),
    # * a {#body} (variable length),
    # * an optional TFC padding ({#tfc}, variable length),
    # * an optional {#padding} (to align ESP on 32-bit boundary, variable length),
    # * a {#pad_length} ({Int8}),
    # * a Next header field ({#next}, +Int8+),
    # * and an optional Integrity Check Value ({#icv}, variable length).
    #
    # == Create an ESP header
    #  # standalone
    #  esp = PacketGen::Header::ESP.new
    #  # in a packet
    #  pkt = PacketGen.gen('IP').add('ESP')
    #  # access to ESP header
    #  pkt.esp   # => PacketGen::Header::ESP
    #
    class ESP < Struct.new(:spi, :sn, :body, :tfc, :padding,
                           :pad_length, :next, :icv)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # ICV (Integrity Check Value) length
      # @return [Integer]
      attr_accessor :icv_length

      # @param [Hash] options
      # @option options [Integer] :icv_length ICV length
      # @option options [Integer] :spi Security Parameters Index
      # @option options [Integer] :sn Sequence Number
      # @option options [::String] :body ESP payload data
      # @option options [::String] :tfc Traffic Flow Confidentiality, random padding
      #    up to MTU
      # @option options [::String] :padding ESP padding to align ESP on 32-bit
      #    boundary
      # @option options [Integer] :pad_length padding length
      # @option options [Integer] :next Next Header field
      # @option options [::String] :icv Integrity Check Value
      def initialize(options={})
        @icv_length = options[:icv_length] || 0
        super Int32.new(options[:spi]),
              Int32.new(options[:sn]),
              StructFu::String.new.read(options[:body]),
              StructFu::String.new.read(options[:tfc]),
              StructFu::String.new.read(options[:padding]),
              Int8.new(options[:pad_length]),
              Int8.new(options[:next]),
              StructFu::String.new.read(options[:icv])
      end

      # Read a ESP packet from string.
      #
      # {#padding} and {#tfc} are not set as they are enciphered (impossible
      # to guess their respective size). {#pad_length} and {#next} are also
      # enciphered.
      # @param [String] str
      # @return [self]
      def read(str)
        return self if str.nil?
        raise ParseError, 'string too short for ESP' if str.size < self.sz
        force_binary str
        self[:spi].read str[0, 4]
        self[:sn].read str[4, 4]
        self[:body].read str[8, -@icv_length-2]
        self[:tfc].read ''
        self[:padding].read ''
        self[:pad_length].read str[-@icv_length-2, 1]
        self[:next].read str[-@icv_length-1, 1]
        self[:icv].read str[-@icv_length, @icv_length]
      end

      # Getter for SPI attribute
      # @return [Integer]
      def spi
        self[:spi].to_i
      end

      # Setter for SPI attribute
      # @param [Integer] val
      # @return [Integer]
      def spi=(val)
        typecast val
      end

      # Getter for SN attribute
      # @return [Integer]
      def sn
        self[:sn].to_i
      end

      # Setter for SN attribute
      # @param [Integer] val
      # @return [Integer]
      def sn=(val)
        typecast val
      end

      # Getter for +pad_length+ attribute
      # @return [Integer]
      def pad_length
        self[:pad_length].to_i
      end

      # Setter for +pad_length+ attribute
      # @param [Integer] val
      # @return [Integer]
      def pad_length=(val)
        typecast val
      end

      # Getter for +next+ attribute
      # @return [Integer]
      def next
        self[:next].to_i
      end

      # Setter for +next+ attribute
      # @param [Integer] val
      # @return [Integer]
      def next=(val)
        typecast val
      end

      # Encrypt in-place ESP payload and trailer.
      # @param [OpenSSL::Cipher] cipher keyed cipher
      # @param [String] iv full IV for encryption
      #  * CTR and GCM modes: +iv+ is 8-bytes long.
      # @param [Hash] options
      # @option options [Boolean] :tfc
      # @option options [String] :salt salt value for CTR and GCM modes
      # @option options [Fixnum] :mtu MTU used for TFC (default 1480).
      #   This is the maximum size for ESP packet (without IP header
      #   nor Eth one).
      # @option options [Fixnum] :esn 32 high-orber bits of ESN
      # @option options [Fixnum] :pad_length set a padding length
      # @option options [String] :padding set a padding. No check with
      #   +:pad_length+ is made. If +:pad_length+ is not set, +:padding+
      #   length is shortened to correct padding length
      # @return [void]
      def encrypt!(ciher, iv, options={})
        raise NotImplementedError
      end

      # Decrypt in-place ESP payload and trailer.
      # @param [OpenSSL::Cipher] cipher keyed cipher
      # @param [Hash] options
      # @option options [Boolean] :parse parse deciphered payload to retrieve
      #   headers (default: +true+)
      # @option options [Fixnum] :icv_len ICV length for captured packets,
      #   or read from PCapNG files
      # @option options [String] :salt salt value for CTR and GCM modes
      # @option options [String] :ctr block-counter value for mode CTR
      # @option options [Fixnum] :esn 32 high-orber bits of ESN
      # @return [Boolean] +true+ if ESP packet is authenticated
      def decrypt!(cipher, options={})
        raise NotImplementedError
      end
    end

    IP.bind_header ESP, protocol: 50
    IPv6.bind_header ESP, next: 50
    UDP.bind_header ESP, sport: 4500, sport: 4500
  end
end
