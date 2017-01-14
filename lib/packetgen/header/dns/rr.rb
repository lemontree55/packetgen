module PacketGen
  module Header
    class DNS

      # DNS Ressource Record
      # @author Sylvain Daubert
      class RR < Struct.new(:name, :type, :rrclass, :ttl, :rdlength, :rdata)
        include StructFu
        include BaseRR

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
          'TSIG'     => 250
        }

        # Ressource Record classes
        CLASSES = {
          'IN' => 1,
          'CH' => 3,
          'HS' => 4
        }

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
          super Name.new(dns).parse(options[:name]),
                Int16.new,
                Int16.new,
                Int32.new(options[:ttl]),
                Int16.new(options[:rdlength]),
                StructFu::String.new.read(options[:rdata])
          if options[:rdata] and options[:rdlength].nil?
            self[:rdlength].read self[:rdata].size
          end
          self.type = options[:type] || 'A'
          self.rrclass = options[:rrclass] || 'IN'
        end

        # Read DNS Ressource Record from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          return self if str.nil?
          force_binary str
          self[:name].read str
          self[:type].read str[self[:name].sz, 2]
          self[:rrclass].read str[self[:name].sz+2, 2]
          self[:ttl].read str[self[:name].sz+4, 4]
          self[:rdlength].read str[self[:name].sz+8, 2]
          self[:rdata].read str[self[:name].sz+10, self.rdlength]
          self
        end
        
        # Getter for ttl
        # @return [Integer]
        def ttl
          self[:ttl].to_i
        end

        # Setter for ttl
        # @param [Integer] val
        # @return [Integer]
        def ttl=(val)
          self[:ttl].read val
        end

        # Getter for rdlength
        # @return [Integer]
        def rdlength
          self[:rdlength].to_i
        end

        # Setter for rdlength
        # @param [Integer] val
        # @return [Integer]
        def rdlength=(val)
          self[:rdlength].read val
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

          case type
          when TYPES['NS'], TYPES['PTR'], TYPES['CNAME']
            str = Name.new(@dns).read(self[:rdata]).to_human
          when TYPES['SOA']
            mname = Name.new(@dns).read(self[:rdata])
            rname = Name.new(@dns).read(self[:rdata][mname.sz..-1])
            serial = Int32.new.read(self[:rdata][mname.sz+rname.sz, 4])
            refresh = Int32.new.read(self[:rdata][mname.sz+rname.sz+4, 4])
            retryi = Int32.new.read(self[:rdata][mname.sz+rname.sz+8, 4])
            expire = Int32.new.read(self[:rdata][mname.sz+rname.sz+12, 4])
            minimum = Int32.new.read(self[:rdata][mname.sz+rname.sz+16, 4])
            str = "#{mname.to_human} #{rname.to_human} #{serial.to_i} #{refresh.to_i} " \
                  "#{retryi.to_i} #{expire.to_i} #{minimum.to_i}"
          when TYPES['MX']
            pref = Int16.new.read(self[:rdata][0, 2])
            exchange = Name.new(@dns).read(self[:rdata][2..-1]).to_human
            str = '%u %s' % [pref.to_i, exchange]
          end

          str
        end

        # @return [String]
        def to_human
          "#{human_type} #{human_rrclass} #{name.to_human} TTL #{ttl} #{human_rdata}"
        end
      end
    end
  end
end
