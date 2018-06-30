# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DNS

      # DNS Question
      # @author Sylvain Daubert
      class Question < Base

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
          'SRV'      => 33,
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
        }.freeze

        # Ressource Record classes
        CLASSES = {
          'IN'   => 1,
          'CH'   => 3,
          'HS'   => 4,
          'NONE' => 254,
          '*'    => 255
        }.freeze

        # @!attribute name
        #  Question domain name
        #  @return [String]
        define_field :name, Name, default: '.'
        # @!attribute type
        #  16-bit question type
        #  @return [Integer]
        define_field :type, Types::Int16Enum, default: 1, enum: TYPES
        # @!attribute rrclass
        #  16-bit question class
        #  @return [Integer]
        define_field :rrclass, Types::Int16Enum, default: 1, enum: CLASSES

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
          if self[:name].dns.is_a? MDNS
            self.class::CLASSES.key(self.rrclass & 0x7fff) || "0x%04x" % (self.rrclass & 0x7fff)
          else
            self.class::CLASSES.key(self.rrclass) || "0x%04x" % self.rrclass
          end
        end

        # @return [String]
        def to_human
          if self[:name].dns.is_a? MDNS
            unicast_bit = (self.rrclass & 0x8000 == 0x8000) ? 'QU' : 'QM'
            "#{human_type} #{human_rrclass} #{unicast_bit} #{name}"
          else
            "#{human_type} #{human_rrclass} #{name}"
          end
        end
      end
    end
  end
end
