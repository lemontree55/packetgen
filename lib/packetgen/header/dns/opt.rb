require_relative 'option'

module PacketGen
  module Header
    class DNS

      # OPT pseudo-RR. Used by Extended DNS (EDNS(0), cf. RFC 6891).
      #
      # a OPT record may contain zero or more {Option options} in its {rdata}.
      # @author Sylvain Daubert
      class OPT < RR
        extend HeaderClassMethods

        # @return [Array<Option>]
        attr_reader :options

        def initialize(dns, options={})
          super
          @options = []
        end

        # @overload ext_rcode=(v)
        #  Setter for upper 8 bits of extended 12-bit RCODE
        #  @param [Integer] v
        #  @return [Integer]
        # @overload ext_rcode
        #  Getter for upper 8 bits of extended 12-bit RCODE
        #  @return [Integer]
        # @return [Integer]
        def ext_rcode=(v=nil)
          if v
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~(0xff << 24))
            self[:ttl].value |= (v & 0xff) << 24
          end
          (self[:ttl].to_i >> 24) & 0xff
        end
        alias ext_rcode ext_rcode=

        # @overload version=(v)
        #  Setter EDNS version
        #  @param [Integer] v
        #  @return [Integer]
        # @overload version
        #  Getter for EDNS version
        #  @return [Integer]
        # @return [Integer]
        def version=(v=nil)
          if v
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~(0xff << 16))
            self[:ttl].value |= (v & 0xff) << 16
          end
          (self[:ttl].to_i >> 16) & 0xff
        end
        alias version version=

        # @overload do=(v)
        #  Setter EDNS do
        #  @param [Boolean] v
        #  @return [Boolean]
        # @overload do?
        #  Getter for EDNS do
        #  @return [Boolean]
        # @return [Boolean]
        def do=(v=nil)
          v = v ? 1 : 0
          if v
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~(1 << 15))
            self[:ttl].value |= (v & 1) << 16
          end
          ((self[:ttl].to_i >> 15) & 1) == 1 ? true : false
        end
        alias :do? :do=

        # @overload z=(v)
        #  @param [Integer] v
        #  @return [Integer]
        # @overload z
        #  @return [Integer]
        # @return [Integer]
        def z=(v=nil)
          if v
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~0x7f)
            self[:ttl].value |= v & 0x7f
          end
          self[:ttl].to_i & 0x7f
        end
        alias z z=

        # @!attribute udp_size
        #  @return [Integer] UDP payload size
        alias udp_size rrclass
        alias udp_size= rrclass=

        # @return [String]
        def human_flags
          do? ? 'do' : 'none'
        end

        # @return [String]
        def human_options
          str = @options.map(&:to_human).join(';')
          str.empty? ? 'none' : str
        end

        # @return [String]
        def to_human
          "#{name.to_human} #{human_type} UDP size:#{udp_size} " \
          "extRCODE:#{ext_rcode} EDNSversion:#{version} flags:#{human_flags} " \
          "options:#{human_options}"
        end

        # @return [String]
        def to_s
          super + @options.map(&:to_s).join
        end
      end
    end
  end
end
