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

      # IP protocol number for ESP
      IP_PROTOCOL = 50

      # Well-known UDP port for ESP
      UDP_PORT = 4500

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
        self[:body].read str[8...-@icv_length-2]
        self[:tfc].read ''
        self[:padding].read ''
        self[:pad_length].read str[-@icv_length-2, 1]
        self[:next].read str[-@icv_length-1, 1]
        self[:icv].read str[-@icv_length, @icv_length] if @icv_length
        self
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
      #
      # This method removes all data from +tfc+ and +padding+ fields, as their
      # enciphered values are concatenated into +body+.
      #
      # It also removes headers under ESP from packet, as they are enciphered in
      # ESP body, and then are no more accessible.
      # @param [OpenSSL::Cipher] cipher keyed cipher.
      #   This cipher is confidentiality-only one, or AEAD one. To use a second
      #   cipher to add integrity, use +:intmode+ option.
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
      # @option options [OpenSSL::HMAC] :intmode integrity mode to use with a
      #   confidentiality-only cipher. Only HMAC are supported.
      # @return [self]
      def encrypt!(cipher, iv, options={})
        opt = { :salt => '' }.merge(options)

        cipher.iv = opt[:salt] + iv

        if cipher.authenticated?
          cipher.auth_data = get_auth_data(opt)
        elsif opt[:intmode]
          opt[:intmode].reset
          opt[:intmode].update get_auth_data(opt)
        end

        opt[:intmode].update self.body.to_s if opt[:intmode]
        self[:body] = StructFu::String.new(iv + cipher.update(self.body.to_s))
        cipher_len = self.body.size

        mode = get_mode(cipher)
        case mode
        when 'cbc'
          self.pad_length = (16 - (cipher_len % 16)) % 16
        else
          self.pad_length = 0
        end

        mod4 = to_s.size % 4
        self.pad_length += 4 - mod4 if mod4 > 0
        if opt[:pad_length]
          self.pad_length = opt[:pad_length]
          self[:padding].read(opt[:padding] || (1..self.pad_length).to_a.pack("C*"))
        else
          padding = opt[:padding] || (1..self.pad_length).to_a.pack("C*")
          self[:padding].read padding[0...self.pad_length]
        end

        unless self.pad_length == 0
          opt[:intmode].update self[:padding] if opt[:intmode]
          self.body += cipher.update(self[:padding])
          self[:padding].read ''
        end
        opt[:intmode].update self[:pad_length].to_s if opt[:intmode]
        self[:pad_length].read cipher.update(self[:pad_length].to_s)
        opt[:intmode].update self[:next].to_s if opt[:intmode]
        self[:next].read cipher.update(self[:next].to_s)
        # as padding is used to pad for CBC mode, this is unused
        cipher.final

        if cipher.authenticated?
          self[:icv].read cipher.auth_tag[0, self.icv_length]
        elsif opt[:intmode]
          self[:icv].read opt[:intmode].digest[0, self.icv_length]
        end

        # Remove enciphered headers from packet
        id = header_id(self)
        if id < packet.headers.size - 1
          (packet.headers.size-1).downto(id+1) do |index|
            packet.headers.delete_at index
          end
        end

        self
      end

      # Decrypt in-place ESP payload and trailer.
      # @param [OpenSSL::Cipher] cipher keyed cipher
      #   This cipher is confidentiality-only one, or AEAD one. To use a second
      #   cipher to add integrity, use +:intmode+ option.
      # @param [Hash] options
      # @option options [Boolean] :parse parse deciphered payload to retrieve
      #   headers (default: +true+)
      # @option options [Fixnum] :icv_length ICV length for captured packets,
      #   or read from PCapNG files
      # @option options [String] :salt salt value for CTR and GCM modes
      # @option options [Fixnum] :esn 32 high-orber bits of ESN
      # @option options [OpenSSL::HMAC] :intmode integrity mode to use with a
      #   confidentiality-only cipher. Only HMAC are supported.
      # @return [Boolean] +true+ if ESP packet is authenticated
      def decrypt!(cipher, options={})
        opt = { :salt => '' }.merge(options)

        mode = get_mode(cipher)
        case mode
        when 'gcm'
          iv_size = 8
          cipher.iv = opt[:salt] + self.body.slice!(0, 8)
        else
          iv_size = 16
          cipher.iv = self.body.slice!(0, 16)
        end

        if @icv_len == 0 or opt[:icv_len]
          raise 'unknown ICV size' unless opt[:icv_len]
          @icv_len = opt[:icv_len].to_i
          # reread ESP to handle new ICV size
          msg = self.body.to_s + self[:pad_length].to_s
          msg += self[:next].to_s
          self[:icv].read msg.slice!(-@icv_len, @icv_len)
          self[:body].read msg[0..-3]
          self[:pad_length].read msg[-2]
          self[:next].read msg[-1]
        end

        if cipher.authenticated?
          cipher.auth_tag = self[:icv]
          cipher.auth_data = get_auth_data(opt)
        elsif opt[:intmode]
          opt[:intmode].reset
          opt[:intmode].update get_auth_data(opt)
        end
        private_decrypt cipher, iv_size, opt
      end

      private

      def get_mode(cipher)
        mode = cipher.name.match(/-([^-]*)$/)[1]
        raise 'unknown cipher mode' if mode.nil?
        mode.downcase
      end

      def get_auth_data(opt)
        ad = self[:spi].to_s
        ad << StructFu::Int32.new(opt[:esn]).to_s if opt[:esn]
        ad << self[:sn].to_s
      end

      def private_decrypt(cipher, iv_size, options)
        # decrypt
        self.body = cipher.update(self.body.to_s)
        options[:intmode].update self.body.to_s if options[:intmode]
        self[:pad_length].read cipher.update(self[:pad_length].to_s)
        options[:intmode].update self[:pad_length].to_s if options[:intmode]
        self[:next].read cipher.update(self[:next].to_s)
        options[:intmode].update self[:next].to_s if options[:intmode]

        # check authentication tag
        begin
          if cipher.authenticated?
            cipher.final
          elsif options[:intmode]
            return false unless options[:intmode].digest == self[:icv]
          end
        rescue OpenSSL::Cipher::CipherError
          return false
        end

        # Set padding
        if self.pad_length > 0
          len = self.pad_length
          self[:padding].read self.body.slice!(-len, len)
        end

        # Set TFC padding
        encap_length = 0
        pkt = nil
        case self.next
        when 4   # IPv4
        pkt = Packet.parse(body, first_header: 'IP')
        encap_length = pkt.ip.length
        when 41  # IPv6
          pkt = Packet.parse(body, first_header: 'IPv6')
          encap_length = pkt.ip6.length + ip6.sz
        when UDP::IP_PROTOCOL
          pkt = Packet.parse(body, first_header: 'UDP')
          encap_length = pkt.udp.length
        when TCP::IP_PROTOCOL
          # No length in TCP header, so TFC may not be used.
          pkt = Packet.parse(body, first_header: 'TCP')
          encap_length = pkt.sz
        else
          raise "Unmanaged encapsulated protocol #{esp_next}"
        end

        if encap_length < body.length
          tfc_len = body.length - encap_length
          self[:esp_tfc].read self.body.slice!(encap_length, tfc_len)
        end

        packet.encapsulate pkt
        true
      end
    end

    IP.bind_header ESP, protocol: ESP::IP_PROTOCOL
    IPv6.bind_header ESP, next: ESP::IP_PROTOCOL
    UDP.bind_header ESP, dport: ESP::UDP_PORT, sport: ESP::UDP_PORT
    ESP.bind_header IP, next: 4
    ESP.bind_header IPv6, next: 41
    ESP.bind_header TCP, next: TCP::IP_PROTOCOL
    ESP.bind_header UDP, next: TCP::IP_PROTOCOL
  end
end
