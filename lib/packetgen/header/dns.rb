# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header

    # DNS: Domain Name Service
    #
    # A DNS packet consists of a header:
    #                                  1  1  1  1  1  1
    #    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                      ID                       |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                    QDCOUNT                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                    ANCOUNT                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                    NSCOUNT                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                    ARCOUNT                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # A DNS packet also contains up to 4 sections:
    # * {#qd}, question section,
    # * {#an}, answer section,
    # * {#ns}, authoritary section,
    # * {#ar}, additional information section.
    #
    # == Create a DNS header
    #  # standalone
    #  dns = PacketGen::Header::DNS.new
    #  # in a IP packet
    #  pkt = PacketGen.gen('IP').add('DNS')
    #  # access to DNS header
    #  pkt.dns   # => PacketGen::Header::DNS
    #
    # == DNS attributes
    #  dns.id = 0x1234
    #  dns.qr = false
    #  dns.opcode = 0xe
    #  dns.opcode = 'query'
    #  dns.aa = dns.tc = dns.rd = dns.ra = false
    #  dns.rcode = 0xa
    #  dns.rcode = 'refused'
    #  dns.qdcount = 123
    #  dns.ancount = 0x1234
    #  dns.nscount = 1
    #  dns.arcount = 0
    # One can also access to DNS sections:
    #  dns.qd   # => PacketGen::Header::DNS::QDSection
    #  dns.an   # => PacketGen::Header::DNS::RRSection
    #  dns.ns   # => PacketGen::Header::DNS::RRSection
    #  dns.ar   # => PacketGen::Header::DNS::RRSection
    #
    # == Add a question to DNS question section
    # Adding a {Question} with {QDSection#<<} automagically increments {#qdcount}.
    # To not modify +qdcount+, use {QDSection#push}.
    #  # add a question about example.net IP address. Increment qdcount
    #  dns.qd << PacketGen::Header::DNS::Question.new(dns, name: 'example.net')
    #  # or
    #  dns.qd << { rtype: 'Question', name: 'example.net' }
    #  # add a question about example.net IPv6 address. Dot not modify qdcount
    #  dns.qd.push PacketGen::Header::DNS::Question.new(dns, name: 'example.net', type: 'AAAA')
    #  # or
    #  dns.qd.push({ rtype: 'Question', name: 'example.net', type: 'AAAA' })
    #
    # == Add a ressource record to a DNS section
    # Adding a {RR} with {RRSection#<<} automagically increments section counter.
    # To not modify it, use {RRSection#push}
    #  # add a RR to answer section. Increment ancount
    #  dns.an << PacketGen::Header::DNS::RR.new(dns, name: 'example.net', rdata: IPAddr.new('1.2.3.4').hton)
    #  # or
    #  dns.an << { rtype: 'RR', name: 'example.net', rdata: IPAddr.new('1.2.3.4').hton }
    #  # add a RR to NS section. Dot not modify nscount
    #  rdata = PacketGen::Header::DNS::Name.new(dns).parse('dns.net')
    #  dns.ns.push PacketGen::Header::DNS::RR.new(dns, name: 'example.net', type: 'NS', rdata: rdata)
    #  # or
    #  dns.ns.push(rtype: 'RR', name: 'example.net', type: 'NS', rdata: rdata)
    #
    # == Extended DNS EDNS(0)
    #  # Add an OPT to ar section
    #  dns.ar << PacketGen::Header::DNS::OPT.new(dns, udp_size: 4096, ext_rcode: 43)
    #  # or
    #  dns.ar << { rtype: 'OPT', udp_size: 4096, ext_rcode: 43 }
    #  # add an option to OPT record
    #  dns.ar.last.options << PacketGen::Header::DNS::Option.new(code: 48, length: 2, data: "12")
    # @author Sylvain Daubert
    class DNS < Base
    end
  end
end

require_relative 'dns/rrsection'
require_relative 'dns/qdsection'
require_relative 'dns/name'
require_relative 'dns/question'
require_relative 'dns/rr'
require_relative 'dns/opt'

module PacketGen
  module Header
    class DNS
      # Port number for DNS over UDP
      UDP_PORT = 53
      # Port number for DNS over TCP
      TCP_PORT = UDP_PORT

      # DNS opcodes
      OPCODES = {
        'query'  => 0,
        'iquery' => 1,
        'status' => 2,
        'notify' => 4,
        'update' => 5
      }

      # DNS Response codes
      RCODES = {
        'ok'              => 0,
        'no-error'        => 0,
        'format-error'    => 1,
        'server-failure'  => 2,
        'name-error'      => 3,
        'not-implemented' => 4,
        'refused'         => 5
      }

      # @!attribute id
      #  @return [Integer]
      define_field :id, Types::Int16
      # @!attribute u16
      #  @return [Integer]
      define_field :u16, Types::Int16
      # @!attribute qdcount
      #  @return [Integer]
      define_field :qdcount, Types::Int16
      # @!attribute ancount
      #  @return [Integer]
      define_field :ancount, Types::Int16
      # @!attribute nscount
      #  @return [Integer]
      define_field :nscount, Types::Int16
      # @!attribute arcount
      #  @return [Integer]
      define_field :arcount, Types::Int16
      # @!attribute qd
      #  @return [QDSection]
      define_field :qd, QDSection, builder: ->(h,t) { t.new(h, h[:qdcount]) }
      # @!attribute an
      #  @return [RRSection]
      define_field :an, RRSection, builder: ->(h,t) { t.new(h, h[:ancount]) }
      # @!attribute ns
      #  @return [RRSection]
      define_field :ns, RRSection, builder: ->(h,t) { t.new(h, h[:nscount]) }
      # @!attribute ar
      #  @return [RRSection]
      define_field :ar, RRSection, builder: ->(h,t) { t.new(h, h[:arcount]) }

      # @!attribute qr
      #   @return [Boolean] query (+false+) or response (+true+)
      # @!attribute opcode
      #   @return [Integer] Kind of query. See {OPCODES}.
      # @!attribute aa
      #   @return [Boolean] Authoritative answer
      # @!attribute tc
      #   @return [Boolean] Truncation
      # @!attribute rd
      #   @return [Boolean] Recursion Desired
      # @!attribute ra
      #   @return [Boolean] Recursion Available
      # @!attribute ad
      #   @return [Boolean] Authentic Data
      # @!attribute cd
      #   @return [Boolean] Checking Disabled
      # @!attribute rcode
      #   @return [Integer] Response code. See {RCODES}.
      define_bit_fields_on :u16, :qr, :opcode, 4, :aa, :tc, :rd, :ra, :z,
                           :ad, :cd, :rcode, 4

      # Read DNS header and sections from a string
      # @param [String] str binary string
      # @return [self]
      def read(str)
        return self if str.nil?
        force_binary str
        self[:id].read str[0, 2]
        self[:u16].read str[2, 2]
        self[:qdcount].read str[4, 2]
        self[:ancount].read str[6, 2]
        self[:nscount].read str[8, 2]
        self[:arcount].read str[10, 2]
        self[:qd].read str[12..-1] if self.qdcount > 0
        start = 12 + self[:qd].sz
        self[:an].read str[start..-1] if self.ancount > 0
        start += self[:an].sz
        self[:ns].read str[start..-1] if self.nscount > 0
        start += self[:ns].sz
        self[:ar].read str[start..-1] if self.arcount > 0
        self
      end

      # Set opcode
      # @param [Integer,String] value
      # @return [Integer]
      def opcode=(value)
        intg = case value
               when Integer
                 value
               else
                 OPCODES[value.to_s]
               end
        raise ArgumentError, "unknown opcode #{value.inspect}" unless intg
        self.u16 &= 0x87ff
        self.u16 |= (intg & 0xf) << 11
      end

      # Set rcode
      # @param [Integer,String] value
      # @return [Integer]
      def rcode=(value)
        intg = case value
               when Integer
                 value
               else
                 RCODES[value]
               end
        raise ArgumentError, "unknown rcode #{value.inspect}" unless intg
        self.u16 &= 0xfff0
        self.u16 |= intg & 0xf
      end

      # Is message a response
      # @return [Boolean]
      def response?
        qr?
      end

      # Is message a query
      # @return [Boolean]
      def query?
        !qr?
      end

      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        fields.each do |attr|
          if attr == :u16
            flags = [:qr, :aa, :tc, :rd, :ra].select! { |attr| send "#{attr}?" }.
                    map(&:to_s).join(',')
            str << Inspect.shift_level(2)
            str << Inspect::FMT_ATTR % ['Flags', 'flags', flags]
            opcode = '%-10s (%u)' % [OPCODES.key(self.opcode), self.opcode]
            str << Inspect.shift_level(2)
            str << Inspect::FMT_ATTR % ['Integer', 'opcode', opcode]
            rcode = '%-10s (%u)' % [RCODES.key(self.rcode), self.rcode]
            str << Inspect.shift_level(2)
            str << Inspect::FMT_ATTR % ['Integer', 'rcode', rcode]
          else
            str << Inspect.inspect_attribute(attr, self[attr], 2)
          end
        end
        str
      end
    end

    self.add_class DNS
    UDP.bind_header DNS, dport: DNS::UDP_PORT, sport: DNS::UDP_PORT
    TCP.bind_header DNS, dport: DNS::TCP_PORT, sport: DNS::TCP_PORT
  end
end
