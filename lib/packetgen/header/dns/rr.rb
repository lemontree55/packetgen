module PacketGen
  module Header
    class DNS

      # DNS Ressource Record
      # @author Sylvain Daubert
      class RR < Question

        # @!attribute ttl
        #  32-bit time to live
        #  @return [Integer]
        define_field :ttl, Types::Int32
        # @!attribute rdlength
        #  16-bit {#rdata} length
        #  @return [Integer]
        define_field :rdlength, Types::Int16
        # @!attribute rdata
        #  @return [Types::String]
        define_field :rdata, Types::String,
                     builder: ->(rr, t) { t.new('', length_from: rr[:rdlength]) }

        # @param [DNS] dns
        # @param [Hash] options
        # @option options [String] :name domain as a dotted string
        # @option options [Integer,String] :type see {TYPES}. Default to +'A'+
        # @option options [Integer,String] :rrclass see {CLASSES}. Default to +'IN'+
        # @option options [Integer] :ttl
        # @option options [Integer] :rdlength if not provided, automatically set
        #   from +:rdata+ length
        # @option options [String] :rdata
        def initialize(dns, options={})
          super
          if options[:rdata] and options[:rdlength].nil?
            self.rdata = options[:rdata]
          end
        end

        # Set rdata and rdlength from +data+
        # @param [String] data
        # @return [void]
        def rdata=(data)
          self[:rdlength].read data.size
          self[:rdata].read data
        end
        
        # Get human readable rdata
        # @return [String]
        def human_rdata
          str = self[:rdata].inspect

          if self.rrclass == CLASSES['IN']
            case type
            when TYPES['A'], TYPES['AAAA']
              str = IPAddr.new_ntoh(self[:rdata]).to_s
            end
          end

          name = Name.new
          name.dns = @dns
          case type
          when TYPES['NS'], TYPES['PTR'], TYPES['CNAME']
            str = name.read(self[:rdata]).to_human
          when TYPES['SOA']
            mname = name.read(self[:rdata]).dup
            rname = name.read(self[:rdata][mname.sz..-1])
            serial = Types::Int32.new.read(self[:rdata][mname.sz+rname.sz, 4])
            refresh = Types::Int32.new.read(self[:rdata][mname.sz+rname.sz+4, 4])
            retryi = Types::Int32.new.read(self[:rdata][mname.sz+rname.sz+8, 4])
            expire = Types::Int32.new.read(self[:rdata][mname.sz+rname.sz+12, 4])
            minimum = Types::Int32.new.read(self[:rdata][mname.sz+rname.sz+16, 4])
            str = "#{mname.to_human} #{rname.to_human} #{serial.to_i} #{refresh.to_i} " \
                  "#{retryi.to_i} #{expire.to_i} #{minimum.to_i}"
          when TYPES['MX']
            pref = Types::Int16.new.read(self[:rdata][0, 2])
            exchange = name.read(self[:rdata][2..-1]).to_human
            str = '%u %s' % [pref.to_i, exchange]
          end

          str
        end

        # @return [String]
        def to_human
          "#{human_type} #{human_rrclass} #{name} TTL #{ttl} #{human_rdata}"
        end
      end
    end
  end
end
