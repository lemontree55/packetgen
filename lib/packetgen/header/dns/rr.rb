module PacketGen
  module Header
    class DNS

      # DNS Ressource Record
      # @author Sylvain Daubert
      class RR < Question

        define_field :ttl, StructFu::Int32
        define_field :rdlength, StructFu::Int16
        define_field :rdata, StructFu::String

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
            self[:rdlength].read self[:rdata].size
          end
        end

        # Read DNS Ressource Record from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          super
          self[:ttl].read str[self[:name].sz+4, 4]
          self[:rdlength].read str[self[:name].sz+8, 2]
          self[:rdata].read str[self[:name].sz+10, self.rdlength]
          self
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
            serial = StructFu::Int32.new.read(self[:rdata][mname.sz+rname.sz, 4])
            refresh = StructFu::Int32.new.read(self[:rdata][mname.sz+rname.sz+4, 4])
            retryi = StructFu::Int32.new.read(self[:rdata][mname.sz+rname.sz+8, 4])
            expire = StructFu::Int32.new.read(self[:rdata][mname.sz+rname.sz+12, 4])
            minimum = StructFu::Int32.new.read(self[:rdata][mname.sz+rname.sz+16, 4])
            str = "#{mname.to_human} #{rname.to_human} #{serial.to_i} #{refresh.to_i} " \
                  "#{retryi.to_i} #{expire.to_i} #{minimum.to_i}"
          when TYPES['MX']
            pref = StructFu::Int16.new.read(self[:rdata][0, 2])
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
