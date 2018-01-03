# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'socket'

module PacketGen
  module Header

    # A IP header consists of:
    # * a first byte ({#u8} of {Types::Int8} type) composed of:
    #   * a 4-bit {#version} field,
    #   * a 4-bit IP header length ({#ihl}) field,
    # * a Type of Service field ({#tos}, {Types::Int8} type),
    # * a total length ({#length}, {Types::Int16} type),
    # * a ID ({#id}, +Int16+ type),
    # * a {#frag} worg (+Int16+) composed of:
    #   * 3 1-bit flags ({#flag_rsv}, {#flag_df} and {#flag_mf}),
    #   * a 13-bit {#fragment_offset} field,
    # * a Time-to-Live ({#ttl}) field (+Int8+),
    # * a {#protocol} field (+Int8+),
    # * a {#checksum} field (+Int16+),
    # * a source IP address ({#src}, {Addr} type),
    # * a destination IP address ({#dst}, +Addr+ type),
    # * an optional {#options} field ({Types::String} type),
    # * and a {#body} ({Types::String} type).
    #
    # == Create a IP header
    #  # standalone
    #  ip = PacketGen::Header::IP.new
    #  # in a packet
    #  pkt = PacketGen.gen('IP')
    #  # access to IP header
    #  pkt.ip   # => PacketGen::Header::IP
    #
    # == IP attributes
    #  ip.u8 = 0x45
    #  # the same as
    #  ip.version = 4
    #  ip.ihl = 5
    #
    #  ip.length = 0x43
    #  ip.id = 0x1234
    #
    #  ip.frag = 0x2031
    #  # the same as:
    #  ip.flag_mf = true
    #  ip.fragment_offset = 0x31
    #
    #  ip.flag_rsv?  # => Boolean
    #  ip.flag_df?   # => Boolean
    #  ip.flag_mf?   # => Boolean
    #
    #  ip.ttl = 0x40
    #  ip.protocol = 6
    #  ip.checksum = 0xffff
    #  ip.src = '127.0.0.1'
    #  ip.src                # => "127.0.0.1"
    #  ip[:src]              # => PacketGen::Header::IP::Addr
    #  ip.dst = '127.0.0.2'
    #  ip.body.read 'this is a body'
    # @author Sylvain Daubert
    class IP < Base;end

require_relative 'ip/addr'
require_relative 'ip/option'
require_relative 'ip/options'

    class IP

      # IP Ether type
      ETHERTYPE = 0x0800

      # @!attribute u8
      #  First byte of IP header. May be accessed through {#version} and {#ihl}.
      #  @return [Integer] first byte of IP header.
      define_field :u8, Types::Int8, default: 0x45
      # @!attribute tos
      #   @return [Integer] 8-bit Type of Service value
      define_field :tos, Types::Int8, default: 0
      # @!attribute length
      #   @return [Integer] 16-bit IP total length
      define_field :length, Types::Int16, default: 20
      # @!attribute id
      #   @return [Integer] 16-bit ID
      define_field :id, Types::Int16, default: -> { rand(65535) }
      # @!attribute frag
      #   @return [Integer] 16-bit frag word
      define_field :frag, Types::Int16, default: 0
      # @!attribute ttl
      #   @return [Integer] 8-bit Time To Live value
      define_field :ttl, Types::Int8, default: 64
      # @!attribute protocol
      #   @return [Integer] 8-bit upper protocol value
      define_field :protocol, Types::Int8
      # @!attribute checksum
      #   @return [Integer] 16-bit IP header checksum
      define_field :checksum, Types::Int16, default: 0
      # @!attribute src
      #   @return [Addr] source IP address
      define_field :src, Addr, default: '127.0.0.1'
      # @!attribute dst
      #   @return [Addr] destination IP address
      define_field :dst, Addr, default: '127.0.0.1'
      # @!attribute options
      #  @since 2.2.0
      #  @return [Types::String]
      define_field :options, Options, optional: ->(h) { h.ihl > 5 }
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String
      
      # @!attribute version
      #   @return [Integer] 4-bit version attribute
      # @!attribute ihl
      #   @return [Integer] 4-bit IP header length attribute
      define_bit_fields_on :u8, :version, 4, :ihl, 4

      # @!attribute flag_rsv
      #   @return [Boolean] reserved bit from flags
      # @!attribute flag_df
      #   @return [Boolean] Don't Fragment flag 
      # @!attribute flag_mf
      #   @return [Boolean] More Fragment flags
      # @!attribute fragment_offset
      #   @return [Integer] 13-bit fragment offset
      define_bit_fields_on :frag, :flag_rsv, :flag_df, :flag_mf, :fragment_offset, 13

      # Populate object from a binary string
      # @param [String] str
      # @return [Fields] self
      def read(str)
        return self if str.nil?
        force_binary str
        self[:u8].read str[0, 1]
        self[:tos].read str[1, 1]
        self[:length].read str[2, 2]
        self[:id].read str[4, 2]
        self[:frag].read str[6, 2]
        self[:ttl].read str[8, 1]
        self[:protocol].read str[9, 1]
        self[:checksum].read str[10, 2]
        self[:src].read str[12, 4]
        self[:dst].read str[16, 4]
        opt_size = 0
        if self.ihl > 5
          opt_size = (self.ihl - 5) * 4
          self[:options].read str[20, opt_size]
        end
        self[:body].read str[20+opt_size..-1]
        self
      end

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        checksum = (self[:u8].to_i << 8) | self.tos
        checksum += self.length
        checksum += self.id
        checksum += self.frag
        checksum += (self.ttl << 8) | self.protocol
        checksum += (self[:src].to_i >> 16)
        checksum += (self[:src].to_i & 0xffff)
        checksum += self[:dst].to_i >> 16
        checksum += self[:dst].to_i & 0xffff
        checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = ~(checksum % 0xffff ) & 0xffff
        self[:checksum].value = (checksum == 0) ? 0xffff : checksum
      end

      # Compute length and set +length+ field
      # @return [Integer]
      def calc_length
        self[:length].value = self.sz
      end

      # Get IP part of pseudo header checksum.
      # @return [Integer]
      def pseudo_header_checksum
        checksum = self[:src].to_i + self[:dst].to_i
        (checksum >> 16) + (checksum & 0xffff)
      end

      # Send IP packet on wire.
      #
      # When sending packet at IP level, +checksum+ and +length+ fields are set by
      # kernel, so bad IP packets cannot be sent this way. To do so, use {Eth#to_w}.
      # @param [String,nil] iface interface name. Not used
      # @return [void]
      def to_w(iface=nil)
        sock = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
        sockaddrin = Socket.sockaddr_in(0, dst)
        sock.send to_s, 0, sockaddrin
        sock.close
      end

      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        shift = Inspect.shift_level(2)
        to_h.each do |attr, value|
          next if attr == :body
          str << Inspect.inspect_attribute(attr, value, 2)
          if attr == :u8
            str << shift + Inspect::FMT_ATTR % ['', 'version', version]
            str << shift + Inspect::FMT_ATTR % ['', 'ihl', ihl]
          elsif attr == :frag
            flags = flag_rsv? ? %w(RSV) : []
            flags << 'DF' if flag_df?
            flags << 'MF' if flag_mf?
            flags_str = flags.empty? ? 'none' : flags.join(',')
            str << shift + Inspect::FMT_ATTR % ['', 'flags', flags_str]
            foff = Inspect.int_dec_hex(fragment_offset, 4)
            str << shift + Inspect::FMT_ATTR % ['', 'frag_offset', foff]
          end
        end
        str
      end

      # Check version field
      # @see [Base#parse?]
      def parse?
        version == 4 and ihl >= 5
      end
    end

    self.add_class IP

    Eth.bind_header IP, ethertype: IP::ETHERTYPE
    SNAP.bind_header IP, proto_id: IP::ETHERTYPE
    Dot1q.bind_header IP, ethertype: IP::ETHERTYPE
    IP.bind_header IP, protocol: 4
  end
end
