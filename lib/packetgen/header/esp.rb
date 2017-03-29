module PacketGen
  module Header

    # Error about enciphering/deciphering was encountered
    class CipherError < Error;end

    # A ESP header consists of:
    # * a Security Parameters Index (#{spi}, {Types::Int32} type),
    # * a Sequence Number ({#sn}, +Int32+ type),
    # * a {#body} (variable length),
    # * an optional TFC padding ({#tfc}, variable length),
    # * an optional {#padding} (to align ESP on 32-bit boundary, variable length),
    # * a {#pad_length} ({Types::Int8}),
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
    # == Examples
    # === Create an enciphered UDP packet (ESP transport mode), using CBC mode
    #  icmp = PacketGen.gen('IP', src: '192.168.1.1', dst: '192.168.2.1').
    #                   add('ESP', spi: 0xff456e01, sn: 12345678).
    #                   add('UDP', dport: 4567, sport: 45362, body 'abcdef')
    #  cipher = OpenSSL::Cipher.new('aes-128-cbc')
    #  cipher.encrypt
    #  cipher.key = 16bytes_key
    #  iv = 16bytes_iv
    #  esp.esp.encrypt! cipher, iv
    #
    # === Create a ESP packet tunneling a UDP one, using GCM combined mode
    #  # create inner UDP packet
    #  icmp = PacketGen.gen('IP', src: '192.168.1.1', dst: '192.168.2.1').
    #                   add('UDP', dport: 4567, sport: 45362, body 'abcdef')
    #
    #  # create outer ESP packet
    #  esp = PacketGen.gen('IP', src '198.76.54.32', dst: '1.2.3.4').add('ESP')
    #  esp.esp.spi = 0x87654321
    #  esp.esp.sn  = 0x123
    #  esp.esp.icv_length = 16
    #  # encapsulate ICMP packet in ESP one
    #  esp.encapsulate icmp
    #  
    #  # encrypt ESP payload
    #  cipher = OpenSSL::Cipher.new('aes-128-gcm')
    #  cipher.encrypt
    #  cipher.key = 16bytes_key
    #  iv = 8bytes_iv
    #  esp.esp.encrypt! cipher, iv, salt: 4bytes_gcm_salt
    #
    # === Decrypt a ESP packet using CBC mode and HMAC-SHA-256
    #  cipher = OpenSSL::Cipher.new('aes-128-cbc')
    #  cipher.decrypt
    #  cipher.key = 16bytes_key
    #  
    #  hmac = OpenSSL::HMAC.new(hmac_key, OpenSSL::Digest::SHA256.new)
    #
    #  pkt.esp.decrypt! cipher, intmode: hmac    # => true if ICV check OK
    # @author Sylvain Daubert
    class ESP < Base
      include Crypto

      # IP protocol number for ESP
      IP_PROTOCOL = 50

      # Well-known UDP port for ESP
      UDP_PORT = 4500

      # @!attribute spi
      #  32-bit Security Parameter Index
      #  @return [Integer]
      define_field :spi, Types::Int32
      # @!attribute sn
      #  32-bit Sequence Number
      #  @return [Integer]
      define_field :sn, Types::Int32
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String
      # @!attribute tfc
      #  Traffic Flow Confidentiality padding
      #  @return [Types::String,Header::Base]
      define_field :tfc, Types::String
      # @!attribute padding
      #  ESP padding
      #  @return [Types::String,Header::Base]
      define_field :padding, Types::String
      # @!attribute pad_length
      #  8-bit padding length
      #  @return [Integer]
      define_field :pad_length, Types::Int8
      # @!attribute next
      #  8-bit next protocol value
      #  @return [Integer]
      define_field :next, Types::Int8
      # @!attribute icv
      #  Integrity Check Value
      #  @return [Types::String,Header::Base]
      define_field :icv, Types::String

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
        super
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
      # @option options [String] :salt salt value for CTR and GCM modes
      # @option options [Boolean] :tfc
      # @option options [Fixnum] :tfc_size ESP body size used for TFC
      #   (default 1444, max size for a tunneled IPv4/ESP packet).
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
        opt = { salt: '', tfc_size: 1444 }.merge(options)

        set_crypto cipher, opt[:intmode]

        real_iv = force_binary(opt[:salt]) + force_binary(iv)
        real_iv += [1].pack('N') if confidentiality_mode == 'ctr'
        cipher.iv = real_iv

        authenticate_esp_header_if_needed options, iv

        case confidentiality_mode
        when 'cbc'
          cipher_len = self.body.sz + 2
          self.pad_length = (16 - (cipher_len % 16)) % 16
        else
          mod4 = to_s.size % 4
          self.pad_length = 4 - mod4 if mod4 > 0
        end

        if opt[:pad_length]
          self.pad_length = opt[:pad_length]
          padding = force_binary(opt[:padding] || (1..self.pad_length).to_a.pack("C*"))
          self[:padding].read padding
        else
          padding = force_binary(opt[:padding] || (1..self.pad_length).to_a.pack("C*"))
          self[:padding].read padding[0...self.pad_length]
        end

        tfc = ''
        if opt[:tfc]
          tfc_size = opt[:tfc_size] - body.sz
          if tfc_size > 0
            case confidentiality_mode
            when 'cbc'
              tfc_size = (tfc_size / 16) * 16
            else
              tfc_size = (tfc_size / 4) * 4
            end
            tfc = force_binary("\0" * tfc_size)
          end
        end

        msg = self.body.to_s + tfc
        msg += self[:padding].to_s + self[:pad_length].to_s + self[:next].to_s
        enc_msg = encipher(msg)
        # as padding is used to pad for CBC mode, this is unused
        cipher.final

        self[:body] = Types::String.new(iv) << enc_msg[0..-3]
        self[:pad_length].read enc_msg[-2]
        self[:next].read enc_msg[-1]

        # reset padding field as it has no sense in encrypted ESP
        self[:padding].read ''

        set_esp_icv_if_needed

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
        opt = { :salt => '', parse: true }.merge(options)

        set_crypto cipher, opt[:intmode]

        case confidentiality_mode
        when 'gcm'
          iv = self.body.slice!(0, 8)
          real_iv = opt[:salt] + iv
        when 'cbc'
          cipher.padding = 0
          real_iv = iv = self.body.slice!(0, 16)
        when 'ctr'
          iv = self.body.slice!(0, 8)
          real_iv = opt[:salt] + iv + [1].pack('N')
        else
          real_iv = iv = self.body.slice!(0, 16)
        end
        cipher.iv = real_iv

        if authenticated? and (@icv_length == 0 or opt[:icv_length])
          raise ParseError, 'unknown ICV size' unless opt[:icv_length]
          @icv_length = opt[:icv_length].to_i
          # reread ESP to handle new ICV size
          msg = self.body.to_s + self[:pad_length].to_s
          msg += self[:next].to_s
          self[:icv].read msg.slice!(-@icv_length, @icv_length)
          self[:body].read msg[0..-3]
          self[:pad_length].read msg[-2]
          self[:next].read msg[-1]
        end

        authenticate_esp_header_if_needed options, iv, self[:icv]
        private_decrypt cipher, opt
      end

      private

      def encipher(data)
        enciphered_data = @conf.update(data)
        @intg.update(enciphered_data) if @intg
        enciphered_data
      end

      def get_auth_data(opt)
        ad = self[:spi].to_s
        if opt[:esn]
          @esn = Types::Int32.new(opt[:esn])
          ad << @esn.to_s if @conf.authenticated?
        end
        ad << self[:sn].to_s
      end

      def authenticate_esp_header_if_needed(opt, iv, icv=nil)
        if @conf.authenticated?
          @conf.auth_tag = icv if icv
          @conf.auth_data = get_auth_data(opt)
        elsif @intg
          @intg.reset
          @intg.update get_auth_data(opt)
          @intg.update iv
          @icv = icv
        else
          @icv = nil
        end
      end

      def set_esp_icv_if_needed
        return unless authenticated?
        if @conf.authenticated?
          self[:icv].read @conf.auth_tag[0, @icv_length]
        else
          self[:icv].read @intg.digest[0, @icv_length]
        end
      end

      def private_decrypt(cipher, options)
        # decrypt
        msg = self.body.to_s
        msg += self[:padding].to_s + self[:pad_length].to_s + self[:next].to_s
        plain_msg = decipher(msg)

        # check authentication tag
        if authenticated?
          return false unless authenticate!
        end

        # Set ESP fields
        self[:body].read plain_msg[0..-3]
        self[:pad_length].read plain_msg[-2]
        self[:next].read plain_msg[-1]

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
          encap_length = pkt.ipv6.length + pkt.ipv6.sz
        when ICMP::IP_PROTOCOL
          pkt = Packet.parse(body, first_header: 'ICMP')
          # no size field. cannot recover TFC padding
          encap_length = body.sz
        when UDP::IP_PROTOCOL
          pkt = Packet.parse(body, first_header: 'UDP')
          encap_length = pkt.udp.length
        when TCP::IP_PROTOCOL
          # No length in TCP header, so TFC may not be used.
          # Or underlayer protocol should have a size information...
          pkt = Packet.parse(body, first_header: 'TCP')
          encap_length = pkt.sz
        when ICMPv6::IP_PROTOCOL
          pkt = Packet.parse(body, first_header: 'ICMPv6')
          # no size field. cannot recover TFC padding
          encap_length = body.sz
        else
          # Unmanaged encapsulated protocol
          encap_length = body.sz
        end

        if encap_length < body.sz
          tfc_len = body.sz - encap_length
          self[:tfc].read self.body.slice!(encap_length, tfc_len)
        end

        if options[:parse]
          packet.encapsulate pkt unless pkt.nil?
        end

        true
      end
    end

    self.add_class ESP

    IP.bind_header ESP, protocol: ESP::IP_PROTOCOL
    IPv6.bind_header ESP, next: ESP::IP_PROTOCOL
    UDP.bind_header ESP, procs: [ ->(f) { f.dport = f.sport = ESP::UDP_PORT },
                                  ->(f) { (f.dport == ESP::UDP_PORT ||
                                           f.sport == ESP::UDP_PORT) &&
                                          Types::Int32.new.read(f.body[0..3]).to_i > 0 }]
    ESP.bind_header IP, next: 4
    ESP.bind_header IPv6, next: 41
    ESP.bind_header TCP, next: TCP::IP_PROTOCOL
    ESP.bind_header UDP, next: TCP::IP_PROTOCOL
    ESP.bind_header ICMP, next: ICMP::IP_PROTOCOL
    ESP.bind_header ICMPv6, next: ICMPv6::IP_PROTOCOL
  end
end
