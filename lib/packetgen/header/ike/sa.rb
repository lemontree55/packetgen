# coding: utf-8
module PacketGen
  module Header
    class IKE

      # Transform attribute.
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |A|       Attribute Type        |    AF=0  Attribute Length     |
      #   |F|                             |    AF=1  Attribute Value      |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                   AF=0  Attribute Value                       |
      #   |                   AF=1  Not Transmitted                       |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # Such an attribute may have a TLV (Type/length/value) format if AF=0,
      # or a TV format (AF=1).
      # @author Sylvain Daubert
      class Attribute < Types::Fields

        TYPE_KEY_LENGTH = 14

        # @!attribute type
        #  attribute type
        #  @return [Integer]
        define_field :type, Types::Int16
        # @!attribute length
        #  attribute length
        #  @return [Integer]
        define_field :length, Types::Int16
        # @!attribute value
        #  attribute value
        #  @return [Integer]
        define_field :value, Types::Int32

        # @return [Integer]
        def length
          tv_format? ? 2 : self[:length].to_i
        end

        # @return [Integer]
        def value
          tv_format? ? self[:length].to_i : self[:value].to_i
        end

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          return self if str.nil?
          force_binary str
          self[:type].read str[0, 2]
          self[:length].read str[2, 2]
          self[:value].read str[4, 4] unless tv_format?
          self
        end

        # Get binary string
        # @return [String]
        def to_s
          str = self[:type].to_s + self[:length].to_s
          str << self[:value].to_s unless tv_format?
          str
        end

        # Get a human readable string
        # @return [String]
        def to_human
          name = self.class.constants.grep(/TYPE_/).
                 select { |c| self.class.const_get(c) == (type & 0x7fff) }.
                 first || "(type #{type})"
          name = name.to_s.sub(/TYPE_/, '')
          "#{name}=#{value}"
        end

        private

        def tv_format?
          type & 0x8000 == 0x8000
        end
      end

      # Set of {Attribute} in a {Transform}
      # @author Sylvain Daubert
      class Attributes < Types::Array
        set_of Attribute

        HUMAN_SEPARATOR = '/'
      end

      # SA Tranform substructure, ad defined in RFC 7296 §3.3.2
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Last Substruc |   RESERVED    |        Transform Length       |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |Transform Type |   RESERVED    |          Transform ID         |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                      Transform Attributes                     ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      class Transform < Types::Fields

        TYPE_ENCR = 1
        TYPE_PRF  = 2
        TYPE_INTG = 3
        TYPE_DH   = 4
        TYPE_ESN  = 5

        ENCR_DES_IV64          = 1
        ENCR_DES               = 2
        ENCR_3DES              = 3
        ENCR_RC5               = 4
        ENCR_IDEA              = 5
        ENCR_CAST              = 6
        ENCR_BLOWFISH          = 7
        ENCR_3IDEA             = 8
        ENCR_DES_IV32          = 9
        ENCR_AES_CBC           = 12
        ENCR_AES_CTR           = 13
        ENCR_AES_CCM_8         = 14
        ENCR_AES_CCM_12        = 15
        ENCR_AES_CCM_16        = 16
        ENCR_AES_GCM8          = 18
        ENCR_AES_GCM12         = 19
        ENCR_AES_GCM16         = 20
        ENCR_CAMELLIA_CBC      = 23
        ENCR_CAMELLIA_CTR      = 24
        ENCR_CAMELLIA_CCM8     = 25
        ENCR_CAMELLIA_CCM12    = 26
        ENCR_CAMELLIA_CCM16    = 27
        ENCR_CHACHA20_POLY1305 = 28

        PRF_HMAC_MD5      = 1
        PRF_HMAC_SHA1     = 2
        PRF_AES128_XCBC   = 4
        PRF_HMAC_SHA2_256 = 5
        PRF_HMAC_SHA2_384 = 6
        PRF_HMAC_SHA2_512 = 7
        PRF_AES128_CMAC   = 8

        INTG_NONE              = 0
        INTG_HMAC_MD5_96       = 1
        INTG_HMAC_SHA1_96      = 2
        INTG_AES_XCBC_96       = 5
        INTG_HMAC_MD5_128      = 6
        INTG_HMAC_SHA1_160     = 7
        INTG_AES_CMAC_96       = 8
        INTG_AES_128_GMAC      = 9
        INTG_AES_192_GMAC      = 10
        INTG_AES_256_GMAC      = 11
        INTG_HMAC_SHA2_256_128 = 12
        INTG_HMAC_SHA2_384_192 = 13
        INTG_HMAC_SHA2_512_256 = 14

        DH_NONE          = 0
        DH_MODP768       = 1
        DH_MODP1024      = 2
        DH_MODP1536      = 5
        DH_MODP2048      = 14
        DH_MODP3072      = 15
        DH_MODP4096      = 16
        DH_MODP6144      = 17
        DH_MODP8192      = 18
        DH_ECP256        = 19
        DH_ECP384        = 20
        DH_ECP521        = 21
        DH_BRAINPOOLP224 = 27
        DH_BRAINPOOLP256 = 28
        DH_BRAINPOOLP384 = 29
        DH_BRAINPOOLP512 = 30
        DH_CURVE25519    = 31
        DH_CURVE448      = 32

        ESN_NO_ESN = 0
        ESN_ESN    = 1

        # @!attribute last
        #  8-bit last substructure. Specifies whether or not this is the
        #  last Transform Substructure in the Proposal. This field has a value of 0
        #  if this was the last Transform Substructure, and a value of 3 if
        #  there are more Transform Substructures.
        #  @return [Integer]
        define_field :last, Types::Int8
        # @!attribute rsv1
        #  8-bit reserved field
        #  @return [Integer]
        define_field :rsv1, Types::Int8
        # @!attribute length
        #  16-bit proposal length
        #  @return [Integer]
        define_field :length, Types::Int16
        # @!attribute type
        #  8-bit transform type. The Transform Type is the cryptographic
        #  algorithm type (i.e. encryption, PRF, integrity, etc.)
        #  @return [Integer]
        define_field :type, Types::Int8
        # @!attribute rsv2
        #  8-bit reserved field
        #  @return [Integer]
        define_field :rsv2, Types::Int8
        # @!attribute id
        #  16-bit transform ID. The Transform ID is the specific instance of
        #  the proposed transform type.
        #  @return [Integer]
        define_field :id, Types::Int16
        # @!attribute attributes
        #  Set of attributes for this transform
        #  @return [Attributes]
        define_field :attributes, Attributes

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          super
          hlen = self.class.new.sz
          attr_len = length - hlen
          attributes.read(str[hlen, attr_len])
          self
        end

        # Get a human readable string
        # @return [String]
        def to_human
          h = "#{type_name}(#{id_name}"
          h << ",#{attributes.to_human}" if attributes.size > 0
          h << ')'
        end

        def type_name
          name = self.class.constants.grep(/TYPE/).
                 select { |c| self.class.const_get(c) == type }.
                 first || "(type #{type})"
          name.to_s.sub(/TYPE_/, '')
        end

        def id_name
          name = self.class.constants.grep(/#{type_name}_/).
                 select { |c| self.class.const_get(c) == id }.
                 first || "ID #{id}"
           name.to_s.sub(/#{type_name}_/, '')
        end
      end

      # Set of {Tranform} in a {SAProposal}
      # @author Sylvain Daubert
      class Transforms < Types::Array
        set_of Transform
      end

      # SA Proposal, as defined in RFC 7296 §3.3.1
      #                          1                   2                   3
      #      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     | Last Substruc |   RESERVED    |         Proposal Length       |
      #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
      #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     ~                        SPI (variable)                         ~
      #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     |                                                               |
      #     ~                        <Transforms>                           ~
      #     |                                                               |
      #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class SAProposal < Types::Fields

        PROTO_IKE = 1
        PROTO_AH  = 2
        PROTO_ESP = 3

        # @!attribute last
        #  8-bit last substructure. Specifies whether or not this is the
        #  last Proposal Substructure in the SA. This field has a value of 0
        #  if this was the last Proposal Substructure, and a value of 2 if
        #  there are more Proposal Substructures.
        #  @return [Integer]
        define_field :last, Types::Int8
        # @!attribute reserved
        #  8-bit reserved field
        #  @return [Integer]
        define_field :reserved, Types::Int8
        # @!attribute length
        #  16-bit proposal length
        #  @return [Integer]
        define_field :length, Types::Int16
        # @!attribute reserved
        #  8-bit reserved field
        #  @return [Integer]
        define_field :num, Types::Int8
        # @!attribute num
        #  8-bit proposal number. When a proposal is made, the first
        #  proposal in an SA payload MUST be 1, and subsequent proposals MUST
        #  be one more than the previous proposal (indicating an OR of the
        #  two proposals).  When a proposal is accepted, the proposal number
        #  in the SA payload MUST match the number on the proposal sent that
        #  was accepted.
        #  @return [Integer]
        define_field :protocol_id, Types::Int8
        # @!attribute protocol_id
        #  8-bit protocol ID. Specify IPsec protocol currently negociated.
        #  May 1 (IKE), 2 (AH) or 3 (ESP).
        #  @return [Integer]
        define_field :spi_size, Types::Int8
        # @!attribute spi_size
        #  8-bit SPI size. Give size of SPI field. Set to 0 for an initial IKE SA
        #  negotiation, as SPI is obtained from outer header.
        #  @return [Integer]
        define_field :num_trans, Types::Int8
        # @!attribute num_trans
        #  8-bit number of transformations
        #  @return [Integer]
        define_field :spi, Types::String, builder: ->(obj) { Types::String.new('', length_from: obj[:spi_size]) }
        # @!attribute transforms
        #  8-bit set of tranforms for this proposal
        #  @return [Transforms]
        define_field :transforms, Transforms

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          super
          hlen = self.class.new.sz
          tlen = length - hlen
          #puts str[hlen, tlen].unpack('C*').map { |v| "%02x" %v }.join(' ')
          transforms.read(str[hlen, tlen])
          self
        end

        # Get a human readable string
        # @return [String]
        def to_human
          "##{num} #{protocol_name}:#{transforms.to_human}"
        end

        # Get protocol name
        # @return [String]
        def protocol_name
          name = self.class.constants.grep(/PROTO/).
                 select { |c| self.class.const_get(c) == protocol_id }.
                 first || 'proto #{protocol_id}'
          name.to_s.sub(/PROTO_/, '')
        end
      end

      # Set of {SAProposal}
      # @author Sylvain Daubert
      class SAProposals < Types::Array
        set_of SAProposal

        HUMAN_SEPARATOR = '; '
      end

      # Security Assocatiob payload
      # @author Sylvain Daubert
      class SA < Payload
        delete_field :content
        # @!attribute proposals
        #  8-bit set of SA proposals
        #  @return [SAProposals]
        define_field_before :body, :proposals, SAProposals

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          super
          hlen = self.class.new.sz
          plen = length - hlen
          proposals.read str[hlen, plen]
          body.read str[hlen+plen..-1]
          self
        end
      end
    end

    self.add_class IKE::SA
  end
end
