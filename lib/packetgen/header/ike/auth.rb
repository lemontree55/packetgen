# coding: utf-8
module PacketGen
  module Header
    class IKE

      # This class handles Authentication payloads.
      #
      # A AUTH payload consists of the IKE generic payload header (see {Payload})
      # and some specific fields:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Auth Method   |                RESERVED                       |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                      Authentication Data                      ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # These specific fields are:
      # * {#type} (ID type),
      # * {#reserved},
      # * and {#content} (Identification Data).
      # @author Sylvain Daubert
      class Auth < Payload

        # Payload type number
        PAYLOAD_TYPE = 39

        METHOD_RSA_SIGNATURE     = 1
        METHOD_SHARED_KEY        = 2
        METHOD_DSA_SIGNATURE     = 3
        METHOD_ECDSA256          = 9
        METHOD_ECDSA384          = 10
        METHOD_ECDSA512          = 11
        METHOD_PASSWORD          = 12
        METHOD_NULL              = 13
        METHOD_DIGITAL_SIGNATURE = 14

        # @attribute :u32
        #   32-bit word including ID Type and RESERVED fields
        #   @return [Integer]
        define_field_before :content, :u32, Types::Int32
        # @attribute [r] method
        #   8-bit Auth Method
        #   @return [Integer]
        # @attribute reserved
        #   24-bit reserved field
        #   @return [Integer]
        define_bit_fields_on :u32, :method, 8, :reserved, 24

        # Check authentication (see RFC 7296 §2.15)
        # @param [Packet] init_msg first IKE message sent by peer
        # @param [String] nonce my nonce, sent in first message
        # @param [String] sk_p secret key used to compute prf(SK_px, IDx')
        # @param [Integer] prf PRF type to use (see {Transform}+::PRF_*+ constants)
        # @param [String] shared_secret shared secret to use as PSK (shared secret
        #    method only)
        # @param [OpenSSL::X509::Certificate] cert certificate to check AUTH signature,
        #   if not embedded in IKE message
        # @return [Boolean]
        # @note For now, only NULL, SHARED_KEY and RSA, DSA and ECDSA signatures are
        #   supported.
        # @note For certificates, only check AUTH authenticity with given (or guessed
        #   from packet) certificate, but certificate chain is not verified.
        def check?(init_msg: nil, nonce: '', sk_p: '', prf: 1, shared_secret: '',
                   cert: nil)
          raise TypeError, 'init_msg should be a Packet' unless init_msg.is_a?(Packet)
          signed_octets = init_msg.ike.to_s
          signed_octets << nonce
          id = packet.ike.flag_i? ? packet.ike_idi : packet.ike_idr
          signed_octets << prf(prf, sk_p, id.to_s[4, id.length - 4])

          case method
          when METHOD_SHARED_KEY
            auth  = prf(prf(shared_secret, 'Key Pad for IKEv2'), signed_octets)
            auth == content
          when METHOD_RSA_SIGNATURE, METHOD_ECDSA256, METHOD_ECDSA384, METHOD_ECDSA512
            if packet.ike_cert
              # FIXME: Expect a ENCODING_X509_CERT_SIG
              #        Others types not supported for now...
              cert = OpenSSL::X509::Certificate.new(packet.ike_cert.content)
            elsif cert.nil?
              raise CryptoError, 'a certificate should be provided'
            end

            text = cert.to_text
            m = text.match(/Public Key Algorithm: ([a-zA-Z0-9-]+)/)
            digest = case m[1]
                     when 'id-ecPublicKey'
                       m2 = text.match(/NIST CURVE: P-(\d+)/)
                       case m2[1]
                       when '256'
                         OpenSSL::Digest::SHA256.new
                       when '384'
                         OpenSSL::Digest::SHA384.new
                       when '521'
                         OpenSSL::Digest::SHA512.new
                       end
                     when /sha([235]\d+)/
                       OpenSSL::Digest.const_get("SHA#{$1}").new
                     when /sha1/, 'rsaEncryption'
                       OpenSSL::Digest::SHA1.new
                     end
            signature = format_signature(cert.public_key, content.to_s)
            cert.public_key.verify(digest, signature, signed_octets)
          when METHOD_NULL
            true
          else
            raise NotImplementedError, "unsupported method #{human_method}"
          end
        end

        # Set Auth method
        # @param [Integer,String] value
        # @return [Integer]
        def method=(value)
          method = case value
               when Integer
                 value
               else
                 c = self.class.constants.grep(/METHOD_#{value}/).first
                 c ? self.class.const_get(c) : nil
               end
          raise ArgumentError, "unknown auth method #{value.inspect}" unless method
          self[:u32].value = (self[:u32].to_i & 0xffffff) | (method << 24)
        end

        # Get authentication method name
        # @return [String]
        def human_method
          name = self.class.constants.grep(/METHOD_/).
                 select { |c| self.class.const_get(c) == method }.
                 first || "method #{method}"
          name.to_s.sub(/METHOD_/, '')
        end

        # @return [String]
        def inspect
          str = Inspect.dashed_line(self.class, 2)
          fields.each do |attr|
            case attr
            when :body
              next
            when :u32
              str << Inspect.shift_level(2)
              str << Inspect::FMT_ATTR % ['Int8', :method, human_method]
              str << Inspect.inspect_attribute(:reserved, self.reserved, 2)
            else
              str << Inspect.inspect_attribute(attr, self[attr], 2)
            end
          end
          str
        end

        private

        def prf(type, key, msg)
          case type
          when Transform::PRF_HMAC_MD5, Transform::PRF_HMAC_SHA1,
               Transform::PRF_HMAC_SHA2_256, Transform::PRF_HMAC_SHA2_384,
               Transform::PRF_HMAC_SHA2_512
            digestname = Transform.constants.grep(/PRF_/).
                         select { |c| Transform.const_get(c) == type }.first.
                         to_s.sub(/^PRF_HMAC_/, '').sub(/2_/, '')
            digest = OpenSSL::Digest.const_get(digestname).new
          else
            raise NotImplementedError, 'for now, only HMAC-based PRF are supported'
          end
          hmac = OpenSSL::HMAC.new(key, digest)
          hmac << msg
          hmac.digest
        end

        def format_signature(pkey, sig)
          if pkey.is_a?(OpenSSL::PKey::EC)
            # PKey::EC need a signature as a DER string representing a sequence of
            # 2 integers: r and s
            r = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(sig[0, sig.size / 2], 2).to_i)
            s = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(sig[sig.size / 2,
                                                               sig.size / 2], 2).to_i)
            OpenSSL::ASN1::Sequence.new([r, s]).to_der
          else
            sig
          end
        end
      end
    end
  end
end

