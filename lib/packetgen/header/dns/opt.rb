require_relative 'option'

module PacketGen
  module Header
    class DNS

      # OPT pseudo-RR. Used by Extended DNS (EDNS(0), cf. RFC 6891).
      #
      # a OPT record may contain zero or more {Option options} in its {#rdata}.
      # @author Sylvain Daubert
      class OPT < RR
        # @return [Array<Option>]
        attr_reader :options

        # @param [DNS] dns
        # @param [Hash] options
        # @option options [String] :name domain as a dotted string. Default to +"."+
        # @option options [Integer,String] :type see {TYPES}. Default to +'OPT'+
        # @option options [Integer] :udp_size UDP maximum size. Also +:rrclass+.
        #  Default to 512.
        # @option options [Integer] :ext_rcode
        # @option options [Integer] :version
        # @option options [Boolean] :do DO bit
        # @option options [Integer] :ttl set +ext_rcode+, +version+, +do+ and
        #   +z+ at once
        # @option options [Integer] :rdlength if not provided, automatically set
        #   from +:rdata+ length
        # @option options [String] :rdata
        def initialize(dns, options={})
          opts = { name: '.', rrclass: 512, type: 41 }.merge!(options)
          super dns, opts
          @options = []

          self.udp_size = options[:udp_size] if options[:udp_size]
          self.ext_rcode = options[:ext_rcode] if options[:ext_rcode]
          self.version = options[:version] if options[:version]
          self.do = options[:do] unless options[:do].nil?
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
          b = v ? 1 : 0
          unless v.nil?
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~(1 << 15))
            self[:ttl].value |= (b & 1) << 15
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
            self[:ttl].value = self[:ttl].to_i & (0xffffffff & ~0x7fff)
            self[:ttl].value |= v & 0x7fff
          end
          self[:ttl].to_i & 0x7fff
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
          "#{name} #{human_type} UDPsize:#{udp_size} " \
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
