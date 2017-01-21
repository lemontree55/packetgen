module PacketGen
  module Header
    class DNS

      # DNS Question
      # @author Sylvain Daubert
      class Question < Base

        # @!attribute name
        #  Question domain name
        #  @return [String]
        define_field :name, Name, default: '.'
        # @!attribute type
        #  16-bit question type
        #  @return [Integer]
        define_field :type, Types::Int16, default: 1
        # @!attribute rrclass
        #  16-bit question class
        #  @return [Integer]
        define_field :rrclass, Types::Int16, default: 1

        # Ressource Record types
        TYPES = {
          'A'        => 1,
          'NS'       => 2,
          'MD'       => 3,
          'MF'       => 4,
          'CNAME'    => 5,
          'SOA'      => 6,
          'MB'       => 7,
          'MG'       => 8,
          'MR'       => 9,
          'NULL'     => 10,
          'WKS'      => 11,
          'PTR'      => 12,
          'HINFO'    => 13,
          'MINFO'    => 14,
          'MX'       => 15,
          'TXT'      => 16,
          'AAAA'     => 28,
          'NAPTR'    => 35,
          'KX'       => 36,
          'CERT'     => 37,
          'OPT'      => 41,
          'DS'       => 43,
          'RRSIG'    => 46,
          'NSEC'     => 47,
          'DNSKEY'   => 48,
          'TKEY'     => 249,
          'TSIG'     => 250,
          '*'        => 255
        }

        # Ressource Record classes
        CLASSES = {
          'IN'   => 1,
          'CH'   => 3,
          'HS'   => 4,
          'NONE' => 254,
          '*'    => 255
        }

        # @param [DNS] dns
        # @param [Hash] options
        # @option options [String] :name domain as a dotted string
        # @option options [Integer,String] :type see {TYPES}. Default to +'A'+
        # @option options [Integer,String] :rrclass see {CLASSES}. Default to +'IN'+
        def initialize(dns, options={})
          super(options)
          self[:name].dns = dns
          self.type = options[:type] if options[:type]
          self.rrclass = options[:rrclass] if options[:rrclass]
        end

        # Read DNS question from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          return self if str.nil?
          force_binary str
          self[:name].read str
          self[:type].read str[self[:name].sz, 2]
          self[:rrclass].read str[self[:name].sz+2, 2]
          self
        end

        # Setter for type
        # @param [Integer] val
        # @return [Integer,String]
        def type=(val)
          v = case val
              when String
                self.class::TYPES[val.upcase]
              else
                val
              end
          raise ArgumentError, "unknown type #{val.inspect}" unless v
          self[:type].read v
        end

        # Setter for class
        # @param [Integer] val
        # @return [Integer,String]
        def rrclass=(val)
              v = case val
                  when String
                    self.class::CLASSES[val.upcase]
                  else
                    val
                  end
          raise ArgumentError, "unknown class #{val.inspect}" unless v
          self[:rrclass].read v
        end

        # Check type
        # @param [String] type name
        # @return [Boolean]
        def has_type?(type)
          self.class::TYPES[type] == self.type
        end

        # Get human readable type
        # @return [String]
          def human_type
          self.class::TYPES.key(type) || "0x%04x" % type
        end

        # Get human readable class
        # @return [String]
        def human_rrclass
          self.class::CLASSES.key(self.rrclass) || "0x%04x" % self.rrclass
        end

        # @return [String]
        def to_human
          "#{human_type} #{human_rrclass} #{name}"
        end
      end
    end
  end
end
