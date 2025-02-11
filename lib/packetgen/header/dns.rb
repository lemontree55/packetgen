# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

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
    #  # opcode may be set as an Integer (all values are possible)
    #  # or as a String (only keys from PacketGen::Header::DNS::OPCODES)
    #  dns.opcode = 0xe       # set as integer, value not defined in standard
    #  dns.opcode = 'query'   # set as string
    #  dns.aa = dns.tc = dns.rd = dns.ra = false
    #  # rcode may be set as an Integer (all values are possible)
    #  # or as a String (only keys from PacketGen::Header::DNS::RCODES)
    #  dns.rcode = 11
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
    # To not modify +qdcount+, use +QDSection#push+.
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
    # Adding a {RR} with {RRSection#<< RRSection#<<} automagically increments section counter.
    # To not modify it, use +RRSection#push RRSection#push+
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
    #  dns.ar.last.options << PacketGen::Header::DNS::Option.new(code: 48, data: '12')
    #  # or
    #  dns.ar.last.options << { code: 48, data: '12' }
    # @author Sylvain Daubert
    # @since 1.3.0
    class DNS < Base
    end
  end
end

require_relative 'dns/name'
require_relative 'dns/question'
require_relative 'dns/rr'
require_relative 'dns/opt'
require_relative 'dns/rrsection'
require_relative 'dns/qdsection'

module PacketGen
  module Header
    class DNS
      # Port number for DNS over UDP
      UDP_PORT = 53
      # Port number for DNS over TCP
      TCP_PORT = UDP_PORT

      # DNS opcodes
      OPCODES = {
        'query' => 0,
        'iquery' => 1,
        'status' => 2,
        'notify' => 4,
        'update' => 5
      }.freeze

      # DNS Response codes
      RCODES = {
        'ok' => 0,
        'no-error' => 0,
        'format-error' => 1,
        'server-failure' => 2,
        'name-error' => 3,
        'not-implemented' => 4,
        'refused' => 5
      }.freeze

      # @!attribute id
      #  @return [Integer]
      define_attr :id, BinStruct::Int16
      # @!attribute u16
      #  @return [Integer]
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
      define_bit_attr :u16, qr: 1, opcode: 4, aa: 1, tc: 1, rd: 1, ra: 1, z: 1, ad: 1, cd: 1, rcode: 4
      undef opcode=, rcode=

      # @!attribute qdcount
      #  @return [Integer]
      define_attr :qdcount, BinStruct::Int16
      # @!attribute ancount
      #  @return [Integer]
      define_attr :ancount, BinStruct::Int16
      # @!attribute nscount
      #  @return [Integer]
      define_attr :nscount, BinStruct::Int16
      # @!attribute arcount
      #  @return [Integer]
      define_attr :arcount, BinStruct::Int16
      # @!attribute qd
      #  @return [QDSection]
      define_attr :qd, QDSection, builder: ->(h, t) { t.new(h, h[:qdcount]) }
      # @!attribute an
      #  @return [RRSection]
      define_attr :an, RRSection, builder: ->(h, t) { t.new(h, h[:ancount]) }
      # @!attribute ns
      #  @return [RRSection]
      define_attr :ns, RRSection, builder: ->(h, t) { t.new(h, h[:nscount]) }
      # @!attribute ar
      #  @return [RRSection]
      define_attr :ar, RRSection, builder: ->(h, t) { t.new(h, h[:arcount]) }

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
        super do |attr|
          next unless attr == :u16

          str = inspect_flags

          str << Inspect.shift_level
          opcode = '%-16s (%u)' % [OPCODES.key(self.opcode), self.opcode]
          str << Inspect::FMT_ATTR % ['Integer', 'opcode', opcode]

          str << Inspect.shift_level
          rcode = '%-16s (%u)' % [RCODES.key(self.rcode), self.rcode]
          str << Inspect::FMT_ATTR % ['Integer', 'rcode', rcode]
        end
      end

      private

      def inspect_flags
        flags = %i[qr aa tc rd ra].select! { |flag| send(:"#{flag}?") }.map(&:to_s).join(',')
        str = Inspect.shift_level
        str << Inspect::FMT_ATTR % ['Flags', 'flags', flags]
      end
    end

    self.add_class DNS
    UDP.bind DNS, dport: DNS::UDP_PORT
    UDP.bind DNS, sport: DNS::UDP_PORT
    TCP.bind DNS, dport: DNS::TCP_PORT
    TCP.bind DNS, sport: DNS::TCP_PORT
  end
end
