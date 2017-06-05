require 'openssl'
module PacketGen
  module Header

    # Dissect error
    class DissectError < ParseError; end

    # Simple Network Management Protocol (SNMP)
    # @author Sylvain Daubert
    # @version 2.0.0
    class SNMP < Base
      # Agents listen to this port
      UDP_PORT1 = 161
      # Configuration sinks listen to this port
      UDP_PORT2 = 162

      PDU_GET      = 0
      PDU_NEXT     = 1
      PDU_RESPONSE = 2
      PDU_SET      = 3
      PDU_TRAPv1   = 4
      PDU_BULK     = 5
      PDU_INFORM   = 6
      PDU_TRAPv2   = 7

      # @return [Integer]
      attr_accessor :version
      # @return [String]
      attr_accessor :community
      # @return [PDU]
      attr_accessor :pdu

      define_field :body, Types::String

      def initialize(options={})
        super
        opt = { version: 1, community: 'public' }.merge!(options)
        @version = opt[:version]
        @community = opt[:community]
        @pdu = opt[:pdu] if opt[:pdu]
      end

      def dissect
        asn1 = OpenSSL::ASN1.decode(self.body)
        unless asn1.is_a? OpenSSL::ASN1::Sequence
          raise DissectError, 'first ASN.1 element should be a Sequence'
        end
        unless asn1.value[0].is_a? OpenSSL::ASN1::Integer
          raise DissectError, 'version field should be an Integer'
        end
        @version = asn1.value[0].value.to_i
        unless asn1.value[1].is_a? OpenSSL::ASN1::OctetString
          raise DissectError, 'version field should be an OctetString'
        end
        @community = asn1.value[1].value
        unless asn1.value[2].is_a? OpenSSL::ASN1::ASN1Data
          raise DissectError, 'pdu field should be an ASN1Data'
        end
        @pdu = asn1.value[2].value
        self[:body] = asn1.value[2].to_der
      end

      def inspect
        str = super
        str << Inspect.inspect_attribute(:version, @version, 2)
        str << Inspect.inspect_attribute(:community, @community, 2)
      end
    end

    self.add_class SNMP
    UDP.bind_header SNMP, dport: SNMP::UDP_PORT1, sport: SNMP::UDP_PORT1
    UDP.bind_header SNMP, dport: SNMP::UDP_PORT2, sport: SNMP::UDP_PORT2
  end
end
