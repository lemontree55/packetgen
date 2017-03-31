# coding: utf-8
module PacketGen
  module Header
    class IKE

      # This class handles Identification - Initiator payloads, denoted IDi.
      #
      # A ID payload consists of the IKE generic payload header (see {Payload})
      # and some specific fields:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |   ID Type     |                 RESERVED                      |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                   Identification Data                         ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # These specific fields are:
      # * {#type} (ID type),
      # * {#reserved},
      # * and {#content} (Identification Data).
      # @author Sylvain Daubert
      class IDi < Payload

        # Payload type number
        PAYLOAD_TYPE = 35

        TYPE_IPV4_ADDR   = 1
        TYPE_FQDN        = 2
        TYPE_RFC822_ADDR = 3
        TYPE_IPV6_ADDR   = 5
        TYPE_DER_ASN1_DN = 9
        TYPE_DER_ASN1_GN = 10
        TYPE_KEY_ID      = 11

        # @attribute :u32
        #   32-bit word including ID Type and RESERVED fields
        #   @return [Integer]
        define_field_before :content, :u32, Types::Int32
        # @attribute [r] type
        #   8-bit ID type
        #   @return [Integer]
        # @attribute reserved
        #   24-bit reserved field
        #   @return [Integer]
        define_bit_fields_on :u32, :type, 8, :reserved, 24

        # Set ID type
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
          raise ArgumentError, "unknown message type #{value.inspect}" unless type
          self[:u32].value = (self[:u32].to_i & 0xffffff) | (type << 24)
        end

        # Get ID type name
        # @return [String]
        def human_type
          name = self.class.constants.grep(/TYPE_/).
                 select { |c| self.class.const_get(c) == type }.
                 first || "type #{type}"
          name.to_s.sub(/TYPE_/, '')
        end

        # Get human readable content, from {#type}
        # @return [String]
        def human_content
          case type
          when TYPE_IPV4_ADDR, TYPE_IPV4_ADDR
            IPAddr.ntop(content)
          when TYPE_DER_ASN1_DN, TYPE_DER_ASN1_GN
            OpenSSL::X509::Name.new(content).to_s
          else
            content.inspect
          end
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
              str << Inspect::FMT_ATTR % ['Int8', :type, human_type]
              str << Inspect.inspect_attribute(:reserved, self.reserved, 2)
            else
              str << Inspect.inspect_attribute(attr, self[attr], 2)
            end
          end
          str
        end
      end

      # This class handles Identification - Responder payloads, denoted IDr.
      # See {IDi}.
      # @author Sylvain Daubert
      class IDr < IDi
        # Payload type number
        PAYLOAD_TYPE = 36
      end
    end

    self.add_class IKE::IDi
    self.add_class IKE::IDr
  end
end
