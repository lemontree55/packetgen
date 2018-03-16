module PacketGen
  module Header
    class IKE

      # Base class for IKE payloads. This class may also be used for unknown payloads.
      #
      # This class handles generic IKE payload header:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # to which a {#content} field is added to handle content of unknown payload types.
      # @author Sylvain Daubert
      class Payload < Base
        # @!attribute next
        #  8-bit next payload
        #  @return [Integer]
        define_field :next, Types::Int8
        # @!attribute flags
        #  8-bit flags
        #  @return [Integer]
        define_field :flags, Types::Int8
        # @!attribute length
        #  16-bit payload total length, including generic payload header
        #  @return [Integer]
        define_field :length, Types::Int16
        # @!attribute content
        #  Payload content. Depends on payload. Variable length.
        #  @return [String]
        define_field :content, Types::String

        # Defining a body permits using Packet#parse to parse next IKE payloads.
        define_field :body, Types::String

        # @!attribute critical
        #  critical flag
        #  @return [Boolean]
        # @!attribute hreserved
        #  reserved part of {#flags} field
        #  @return [Integer]
        define_bit_fields_on :flags, :critical, :hreserved, 7

        def initialize(options={})
          super
          self[:length].value = sz unless options[:length]
        end

        # @private
        alias base_read read

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          base_read str
          unless self[:content].nil?
            content_length = length - self.class.new.sz
            if content_length >= 0
              self[:body] = self[:content][content_length..-1]
              self[:content] = self[:content][0, content_length]
            end
          end
          self
        end

        # Compute length and set {#length} field
        # @return [Integer] new length
        def calc_length
          # Here, #body is next payload, so body size should not be taken in
          # account (payload's real body is #content).
          self[:length].value = sz - body.sz
        end
      end
    end

    self.add_class IKE::Payload
  end
end

# here, future payloads to be required
require_relative 'sa'
require_relative 'ke'
require_relative 'nonce'
require_relative 'notify'
require_relative 'sk'
require_relative 'id'
require_relative 'cert'
require_relative 'certreq'
require_relative 'auth'
require_relative 'ts'
require_relative 'vendor_id'

module PacketGen
  module Header
    IKE.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::SA, next: IKE::SA::PAYLOAD_TYPE

    IKE.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::KE, next: IKE::KE::PAYLOAD_TYPE

    IKE.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE

    IKE.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE

    IKE.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::SK, next: IKE::SK::PAYLOAD_TYPE

    IKE.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE

    IKE.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE

    IKE.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE

    IKE.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE

    IKE.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE

    IKE.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE

    IKE.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
    IKE::VendorID.bind_header IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE

    IKE.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::Payload.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::SA.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::KE.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::Nonce.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::Notify.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::SK.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::IDi.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::IDr.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::Cert.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::CertReq.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::Auth.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::TSi.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
    IKE::TSr.bind_header IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE

    # Last defined. To be used as default if no other may be parsed.
    IKE::SA.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::KE.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::Nonce.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::Notify.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::SK.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::IDi.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::IDr.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::Cert.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::CertReq.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::Auth.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::TSi.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::TSr.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::VendorID.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE.bind_header IKE::Payload, next: ->(v) { v > 0 }
    IKE::Payload.bind_header IKE::Payload, next: ->(v) { v > 0 }
  end
end
