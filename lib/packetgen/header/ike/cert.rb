# coding: utf-8
module PacketGen
  module Header
    class IKE

      # This class handles Certificate payloads.
      #
      # A Cert payload consists of the IKE generic payload header (see {Payload})
      # and some specific fields:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Cert Encoding |                                               |
      #   +-+-+-+-+-+-+-+-+                                               +
      #   |                                                               |
      #   ~                       Certificate Data                        ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # These specific fields are:
      # * {#encoding},
      # * and {#content} (Certificate Data).
      # @author Sylvain Daubert
      class Cert < Payload

        # Payload type number
        PAYLOAD_TYPE = 37

        ENCODING_PKCS7_WRAPPED_X509   = 1
        ENCODING_PGP                  = 2
        ENCODING_DNS_SIGNED_KEY       = 3
        ENCODING_X509_CERT_SIG        = 4
        ENCODING_KERBEROS_TOKEN       = 6
        ENCODING_X509_CRL             = 7
        ENCODING_X509_ARL             = 8
        ENCODING_SPKI_CERT            = 9
        ENCODING_X509_CERT_ATTR       = 10
        ENCODING_HASH_URL_X509_CERT   = 12
        ENCODING_HASH_URL_X509_BUNDLE = 13

        # @attribute encoding
        #   8-bit certificate encoding
        #   @return [Integer]
        define_field_before :content, :encoding, Types::Int8

        def initialize(options={})
          super
          self.encoding = options[:encoding] if options[:encoding]
        end

        # Set encoding
        # @param [Integer,String] value
        # @return [Integer]
        def encoding=(value)
          encoding = case value
               when Integer
                 value
               else
                 c = self.class.constants.grep(/ENCODING_#{value}/).first
                 c ? self.class.const_get(c) : nil
               end
          raise ArgumentError, "unknown ID encoding #{value.inspect}" unless encoding
          self[:encoding].value = encoding
        end

        # Get encoding name
        # @return [String]
        def human_encoding
          name = self.class.constants.grep(/ENCODING_/).
                 select { |c| self.class.const_get(c) == encoding }.
                 first || "encoding #{encoding}"
          name.to_s.sub(/ENCODING_/, '')
        end

        # @return [String]
        def inspect
          str = Inspect.dashed_line(self.class, 2)
          fields.each do |attr|
            case attr
            when :body
              next
            when :encoding
              str << Inspect.shift_level(2)
              str << Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''), attr,
                                          human_encoding]
            else
              str << Inspect.inspect_attribute(attr, self[attr], 2)
            end
          end
          str
        end
      end
    end

    self.add_class IKE::Cert
  end
end
