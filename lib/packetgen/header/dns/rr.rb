# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class DNS
      # DNS Ressource Record
      # @author Sylvain Daubert
      class RR < Question
        # @!attribute ttl
        #  32-bit time to live
        #  @return [Integer]
        define_attr :ttl, BinStruct::Int32
        # @!attribute rdlength
        #  16-bit {#rdata} length
        #  @return [Integer]
        define_attr :rdlength, BinStruct::Int16
        # @!attribute rdata
        #  @return [BinStruct::String]
        define_attr :rdata, BinStruct::String,
                    builder: ->(rr, t) { t.new(length_from: rr[:rdlength]) }

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
          return unless options[:rdata] && options[:rdlength].nil?

          self.rdata = options[:rdata]
        end

        undef rdata=

        # Set rdata and rdlength from +data+
        # @param [String] data
        # @return [void]
        def rdata=(data)
          self[:rdlength].from_human(data.size)
          self[:rdata].read(data)
        end

        # rubocop:disable Metrics/AbcSize

        # Get human readable rdata
        # @return [String]
        def human_rdata
          str = human_ip_rdata || self[:rdata].inspect

          case type
          when TYPES['NS'], TYPES['PTR'], TYPES['CNAME']
            name = Name.new
            name.dns = self[:name].dns
            str = name.read(self[:rdata]).to_human
          when TYPES['SOA']
            str = human_soa_rdata
          when TYPES['MX']
            str = human_mx_data
          when TYPES['SRV']
            str = human_srv_data
          end

          str
        end
        # rubocop:enable Metrics/AbcSize

        # Get human readable class
        # @return [String]
        def human_rrclass
          if self[:name].dns.is_a? MDNS
            str = self.class::CLASSES.key(self.rrclass & 0x7fff) || '0x%04x' % (self.rrclass & 0x7fff)
            str += ' CACHE-FLUSH' if (self.rrclass & 0x8000).positive?
            str
          else
            self.class::CLASSES.key(self.rrclass) || '0x%04x' % self.rrclass
          end
        end

        # @return [String]
        def to_human
          "#{human_type} #{human_rrclass} #{name} TTL #{ttl} #{human_rdata}"
        end

        private

        def human_ip_rdata
          # Need to mask: mDNS uses leftmost bit as a flag (CACHE FLUSH)
          return unless self.rrclass & 0x7fff == CLASSES['IN']

          case type
          when TYPES['A'], TYPES['AAAA']
            IPAddr.new_ntoh(self[:rdata]).to_s
          end
        end

        def human_mx_data
          name = Name.new
          name.dns = self[:name].dns

          pref = BinStruct::Int16.new.read(self[:rdata][0, 2])
          exchange = name.read(self[:rdata][2..]).to_human

          '%u %s' % [pref.to_i, exchange]
        end

        # rubocop:disable Metrics/AbcSize
        def human_soa_rdata
          name = Name.new
          name.dns = self[:name].dns
          mname = name.read(self[:rdata]).dup
          rname = name.read(self[:rdata][mname.sz..])

          serial = BinStruct::Int32.new.read(self[:rdata][mname.sz + rname.sz, 4])
          refresh = BinStruct::Int32.new.read(self[:rdata][mname.sz + rname.sz + 4, 4])
          retryi = BinStruct::Int32.new.read(self[:rdata][mname.sz + rname.sz + 8, 4])
          expire = BinStruct::Int32.new.read(self[:rdata][mname.sz + rname.sz + 12, 4])
          minimum = BinStruct::Int32.new.read(self[:rdata][mname.sz + rname.sz + 16, 4])

          "#{mname.to_human} #{rname.to_human} #{serial.to_i} #{refresh.to_i} " \
            "#{retryi.to_i} #{expire.to_i} #{minimum.to_i}"
        end

        def human_srv_data
          name = Name.new
          name.dns = self[:name].dns

          priority = BinStruct::Int16.new.read(self[:rdata][0, 2])
          weight = BinStruct::Int16.new.read(self[:rdata][2, 2])
          port = BinStruct::Int16.new.read(self[:rdata][4, 2])
          target = name.read(self[:rdata][6, self[:rdata].size]).to_human

          "#{priority.to_i} #{weight.to_i} #{port.to_i} #{target}"
        end
        # rubocop:enable Metrics/AbcSize
      end
    end
  end
end
