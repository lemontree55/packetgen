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

        def initialize(options={})
          super
          if tv_format?
            self[:length].value = (options[:value] & 0xffff)
          else
            self[:length].value = 8 unless options[:length]
          end
        end

        # @return [Integer]
        def length
          tv_format? ? 4 : self[:length].to_i
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
                 first || "attr[#{type & 0x7fff}]"
          name = name.to_s.sub(/TYPE_/, '')
          "#{name}=#{value}"
        end

        # Say if attribute use TV format (+true+) or TLV one (+false+)
        # @return [Boolean]
        def tv_format?
          type & 0x8000 == 0x8000
        end
      end

      # Set of {Attribute} in a {Transform}
      # @author Sylvain Daubert
      class Attributes < Types::Array
        set_of Attribute
      end

      # SA Tranform substructure, as defined in RFC 7296 §3.3.2
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
      #
      # == Create a Transform
      #  # using type and id names
      #  trans = PacketGen::Header::IKE::Transform.new(type: 'ENCR', id: 'AES_CBC')
      #  # using integer values
      #  trans = PacketGen::Header::IKE::Transform.new(type: 1, id: 12)
      # == Add attributes to a transform
      #  # using an Attribute object
      #  attr = PacketGen::Header::IKE::Attribute.new(type: 14, value: 128)
      #  trans.attributes << attr
      #  # using a hash
      #  trans.attributes << { type: 14, value: 128 }
      # @author Sylvain Daubert
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
        ENCR_AES_CCM8          = 14
        ENCR_AES_CCM12         = 15
        ENCR_AES_CCM16         = 16
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
        INTG_AES128_GMAC      = 9
        INTG_AES192_GMAC      = 10
        INTG_AES256_GMAC      = 11
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
        # @!attribute [r] type
        #  8-bit transform type. The Transform Type is the cryptographic
        #  algorithm type (i.e. encryption, PRF, integrity, etc.)
        #  @return [Integer]
        define_field :type, Types::Int8
        # @!attribute rsv2
        #  8-bit reserved field
        #  @return [Integer]
        define_field :rsv2, Types::Int8
        # @!attribute [r] id
        #  16-bit transform ID. The Transform ID is the specific instance of
        #  the proposed transform type.
        #  @return [Integer]
        define_field :id, Types::Int16
        # @!attribute attributes
        #  Set of attributes for this transform
        #  @return [Attributes]
        define_field :attributes, Attributes

        def initialize(options={})
          super
          self[:length].value = sz unless options[:length]
          self.type = options[:type] if options[:type]
          self.id = options[:id] if options[:id]
        end

        # Set transform type
        # @param [Integer,String] value
        # @return [Integer]
        def type=(value)
          type = case value
                 when Integer
                   value
                 else
                   c = self.class.constants.grep(/TYPE_#{value}/).first
                   c ? self.class.const_get(c) : nil
                 end
          raise ArgumentError, "unknown type #{value.inspect}" unless type
          self[:type].value = type
        end

        # Set transform ID
        # @param [Integer,String] value
        # @return [Integer]
        def id=(value)
          id = case value
               when Integer
                 value
               else
                 c = self.class.constants.grep(/#{human_type}_#{value}/).first
                 c ? self.class.const_get(c) : nil
               end
          raise ArgumentError, "unknown ID #{value.inspect}" unless id
          self[:id].value = id
        end

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

        # Compute length and set {#length} field
        # @return [Integer] new length
        def calc_length
          self[:length].value = sz
        end

        # Get a human readable string
        # @return [String]
        def to_human
          h = "#{human_type}(#{human_id}"
          h << ",#{attributes.to_human}" if attributes.size > 0
          h << ')'
        end

        # Get human-readable type
        # @return [String]
        def human_type
          name = self.class.constants.grep(/TYPE/).
                 select { |c| self.class.const_get(c) == type }.
                 first || "type[#{type}]"
          name.to_s.sub(/TYPE_/, '')
        end

        # Get human-readable ID
        # @return [String]
        def human_id
          name = self.class.constants.grep(/#{human_type}_/).
                 select { |c| self.class.const_get(c) == id }.
                 first || "ID=#{id}"
           name.to_s.sub(/#{human_type}_/, '')
        end

        # Say if this transform is the last one (from {#last} field)
        # @return [Boolean,nil] returns a Boolean when {#last} has defined value (+0+ => +true+, +3+ => +false+), else +nil+ is returned.
        def last?
          case last
          when 0
            true
          when 3
            false
          else
            nil
          end
        end
      end

      # Set of {Transform} in a {SAProposal}
      # @author Sylvain Daubert
      class Transforms < Types::Array
        set_of Transform

        # Same as {Types::Array#push} but update previous {Transform#last} attribute
        # @see Types::Array#push
        def push(trans)
          super
          self[-2].last = 3 if size > 1
          self[-1].last = 0
          self
        end
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
      #
      # == Create a proposal
      #  # using protocol name
      #  proposal = PacketGen::Header::IKE::Proposal.new(num: 1, protocol: 'IKE')
      #  # using integer values
      #  proposal = PacketGen::Header::IKE::Proposal.new(num: 1, protocol: 1)
      # == Add transforms to a proposal
      #  # using a Transform object
      #  trans = PacketGen::Header::IKE::Transform.new(type: 'ENCR', id: '3DES')
      #  proposal.transforms << trans
      #  # using a hash
      #  proposal.transforms << { type: 'ENCR', id: '3DES' }
      # @author Sylvain Daubert
      class SAProposal < Types::Fields

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
        # @!attribute num
        #  8-bit proposal number. When a proposal is made, the first
        #  proposal in an SA payload MUST be 1, and subsequent proposals MUST
        #  be one more than the previous proposal (indicating an OR of the
        #  two proposals).  When a proposal is accepted, the proposal number
        #  in the SA payload MUST match the number on the proposal sent that
        #  was accepted.
        #  @return [Integer]
        define_field :num, Types::Int8, default: 1
        # @!attribute [r] protocol
        #  8-bit protocol ID. Specify IPsec protocol currently negociated.
        #  May 1 (IKE), 2 (AH) or 3 (ESP).
        #  @return [Integer]
        define_field :protocol, Types::Int8
        # @!attribute spi_size
        #  8-bit SPI size. Give size of SPI field. Set to 0 for an initial IKE SA
        #  negotiation, as SPI is obtained from outer header.
        #  @return [Integer]
        define_field :spi_size, Types::Int8, default: 0
        # @!attribute num_trans
        #  8-bit number of transformations
        #  @return [Integer]
        define_field :num_trans, Types::Int8, default: 0
        # @!attribute spi
        #   the sending entity's SPI. When the {#spi_size} field is zero,
        #   this field is not present in the proposal.
        #   @return [String]
        define_field :spi, Types::String, builder: ->(t) { Types::String.new('', length_from: t[:spi_size]) }
        # @!attribute transforms
        #  8-bit set of tranforms for this proposal
        #  @return [Transforms]
        define_field :transforms, Transforms, builder: ->(t) { Transforms.new(counter: t[:num_trans]) }

        def initialize(options={})
          if options[:spi] and options[:spi_size].nil?
            options[:spi_size] = options[:spi].size
          end
          super
          self[:length].value = sz unless options[:length]
          self.protocol = options[:protocol] if options[:protocol]
        end

        # Set protocol
        # @param [Integer,String] value
        # @return [Integer]
        def protocol=(value)
          proto = case value
               when Integer
                 value
               else
                 c = IKE.constants.grep(/PROTO_#{value}/).first
                 c ? IKE.const_get(c) : nil
               end
          raise ArgumentError, "unknown protocol #{value.inspect}" unless proto
          self[:protocol].value = proto
        end

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          super
          hlen = self.class.new.sz + spi_size
          tlen = length - hlen
          transforms.read(str[hlen, tlen])
          self
        end

        # Compute length and set {#length} field
        # @return [Integer] new length
        def calc_length
          transforms.each { |t| t.calc_length }
          self[:length].value = sz
        end

        # Get a human readable string
        # @return [String]
        def to_human
          str = "##{num} #{human_protocol}"
          case spi_size
          when 4
            str << "(spi:0x%08x)" % Types::Int32.new.read(spi).to_i
          when 8
            str << "(spi:0x%016x)" % Types::Int64.new.read(spi).to_i
          end
          str << ":#{transforms.to_human}"
        end

        # Get protocol name
        # @return [String]
        def human_protocol
          name = IKE.constants.grep(/PROTO/).
                 select { |c| IKE.const_get(c) == protocol }.
                 first || "proto #{protocol}"
          name.to_s.sub(/PROTO_/, '')
        end

        # Say if this proposal is the last one (from {#last} field)
        # @return [Boolean,nil] returns a Boolean when {#last} has defined value
        #    (+0+ => +true+, +2+ => +false+), else +nil+ is returned.
        def last?
          case last
          when 0
            true
          when 2
            false
          else
            nil
          end
        end
      end

      # Set of {SAProposal}
      # @author Sylvain Daubert
      class SAProposals < Types::Array
        set_of SAProposal

        # Separator used between proposals in {#to_human}
        HUMAN_SEPARATOR = '; '

        # Same as {Types::Array#push} but update previous {SAProposal#last} attribute
        # @see Types::Array#push
        def push(prop)
          super
          self[-2].last = 2 if size > 1
          self[-1].last = 0
          self
        end
      end

      # This class handles Security Assocation payloads, as defined in RFC 7296 §3.3.
      #
      # A SA payload contains a generic payload header (see {Payload}) and a set of
      # {SAProposal} ({#proposals} field, which is a {SAProposals} object):
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                          <Proposals>                          ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #
      # == Create a SA payload
      #   # Create a IKE packet with a SA payload
      #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::SA')
      #   # add a proposal. Protocol name is taken from SAProposal::PROTO_* constants
      #   pkt.ike_sa.proposals << { num: 1, protocol: 'ESP' }
      #   # add a transform to this proposal.
      #   # type name is taken from Transform::TYPE_* constants.
      #   # ID is taken from Transform::<TYPE>_* constants.
      #   pkt.ike_sa.proposals.first.transforms << { type: 'ENCR', id: 'AES_CTR' }
      #   # and finally, add an attribute to this transform (here, KEY_SIZE = 128 bits)
      #   pkt.ike_sa.proposals[0].transforms[0].attributes << { type: 0x800e, value: 128 }
      #   pkt.calc_length
      # @author Sylvain Daubert
      class SA < Payload

        # Payload type number
        PAYLOAD_TYPE = 33

        delete_field :content
        # @!attribute proposals
        #  Set of SA proposals
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

        # Compute length and set {#length} field
        # @return [Integer] new length
        def calc_length
          proposals.each { |p| p.calc_length }
          super
        end
      end
    end

    self.add_class IKE::SA
  end
end
