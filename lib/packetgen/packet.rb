# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  # An object of type {Packet} handles a network packet. This packet may contain
  # multiple protocol headers, starting from MAC layer or from Network (OSI) layer.
  #
  # A Packet is created using {.gen} method. Headers may be added to this packet using {#add}.
  # It may also be created from parsing a binary string, using {.parse} method.
  #
  # @example Very simple packet
  #   # Create a packet with a single IP header. IP source and destination addresses are set.
  #   pkt = PacketGen::Packet.gen('IP', src: '192.168.1.1', dst: '192.168.1.2')
  #
  # @example Parsing a binary string
  #  # a IP/ICMP packet, as binary string
  #  binary_string = "E\x00\x00\x1C\xAA`\x00\x00@\x01M-\xC0\xA8\x01\x01\xC0\xA8\x01\x02\x00\b;1abcd".b
  #  pkt = PacketGen::Packet.parse(binary_string)
  #  pkt.is?('IP')    #=> true
  #  pkt.is?('ICMP')  #=> true
  #
  # Information for each level is accessible through the associated header. Header is accessible through a
  # method defined with its name at packet level (i.e. +#ip+ for a IP header).
  #
  # @example Accessing header information
  #   pkt = PacketGen::Packet.gen('IP').add('UDP')
  #   # read information
  #   pkt.udp.sport #=> 0
  #   pkt.ip.ttl    #=> 64
  #   # set information
  #   pkt.udp.dport = 2323
  #   pkt.ip.ttl = 1
  #   # Set multiple attributes at once
  #   pkt.ip(ttl: 1, id: 1234)
  #
  # Packets may be written to files using {#write}:
  #   pkt = PacketGen::Packet.gen('Eth')
  #   pkt.write('file.pcapng')
  #
  # Packets may be captured from network interfaces:
  #   # Capture all packets from default interface. Never end.
  #   PacketGen::Packet.capture do |packet|
  #     do_some_stuffs
  #   end
  #
  #   # Get 5 packets from eth0 interface
  #   packets = Packet.capture(iface: 'eth0', max: 5)
  #
  # Finally, packets may also be read from a file:
  #   packets = Packet.read(file.pcapng)
  # @author Sylvain Daubert
  # @author LemonTree55
  class Packet
    # Get packet headers, ordered as they appear in the packet.
    # @return [Array<Headerable>]
    attr_reader :headers
    # Activaye or deactivate header cache (activated by default)
    # @return [Boolean]
    attr_accessor :cache_headers

    # Create a new Packet
    # @param [String] protocol base protocol for packet
    # @param [Hash] options specific options for +protocol+
    # @return [Packet]
    def self.gen(protocol, options={})
      self.new.add(protocol, options)
    end

    # Parse a binary string and generate a Packet from it.
    #   # auto-detect first header
    #   Packet.parse(str)
    #   # force decoding a Ethernet header for first header
    #   Packet.parse(str, first_header: 'Eth')
    # @param [String] binary_str
    # @param [String,nil] first_header First protocol header. +nil+ means discover it!
    # @return [Packet]
    # @raise [ArgumentError] +first_header+ is an unknown header
    def self.parse(binary_str, first_header: nil)
      new.parse(binary_str, first_header: first_header)
    end

    # Capture packets from wire.
    # Same arguments as {Capture#initialize}
    # @see Capture#initialize
    # @yieldparam [Packet,String] packet if a block is given, yield each
    #    captured packet (Packet or raw data String, depending on +:parse+ option)
    # @yieldparam [Time] timestamp packet timestamp
    # @return [Array<Packet>] captured packet
    # @since 3.3.0 add packet timestamp as second yield parameter
    def self.capture(**kwargs, &block)
      capture = Capture.new(**kwargs)
      if block
        capture.start(&block)
      else
        capture.start
      end
      capture.packets
    end

    # Read packets from +filename+. May read Pcap and Pcap-NG formats.
    #
    # For more control (on Pcap-ng only), see {PcapNG::File}.
    # @param [String] filename PcapNG or Pcap file.
    # @return [Array<Packet>]
    # @raise [ArgumentError] unknown file format
    # @author Sylvain Daubert
    # @author Kent Gruber - Pcap format
    # @since 2.0.0 Also read Pcap format.
    def self.read(filename)
      PcapNG::File.new.read_packets(filename)
    rescue StandardError => e
      raise ArgumentError, e unless File.extname(filename.downcase) == '.pcap'

      Pcap.read(filename)
    end

    # Write packets to +filename+, as pcap or PcapNG file
    #
    # For more options, see {PcapNG::File}.
    # @param [String] filename
    # @param [Array<Packet>] packets packets to write
    # @return [void]
    # @since 4.0.0 write a pcap file if filename extension is +.pcap+
    # @author Sylvain Daubert
    # @author LemonTree55 (pcap)
    def self.write(filename, packets)
      if filename.end_with?('.pcap')
        Pcap.write(filename, packets)
      else
        pf = PcapNG::File.new
        pf.read_array(packets)
        pf.to_f(filename)
      end
    end

    # @private
    def initialize
      @headers = []
      @header_cache = {}
      @cache_headers = true
    end

    # Add a protocol header in packet.
    # @param [String] protocol
    # @param [Hash] options protocol specific options
    # @return [self]
    # @raise [ArgumentError] unknown protocol
    # @raise [BindingError] unknown binding
    # @see #<<
    # @example
    #  pkt = PacketGen::Packet.gen('Eth')
    #  # Add a IP header
    #  pkt.add('IP')
    #  # Add a TCP header, with some attributes and body set
    #  pkt.add('TCP', dport: 80, seqnum: 123456, body: "abcd".b)
    def add(protocol, options={})
      klass = check_protocol(protocol)

      # options[:packet]= self is speedier than options.merge(packet: self)
      options[:packet] = self
      header = klass.new(options)
      add_header(header)
      self
    end

    # Insert a header in packet
    # @param [Header] prev header after which insert new one
    # @param [String] protocol protocol to insert
    # @param [Hash] options protocol specific options
    # @return [self]
    # @raise [BindingError] unknown protocol
    def insert(prev, protocol, options={})
      klass = check_protocol(protocol)

      nxt = prev.body
      # options[:packet]= self is speedier than options.merge(packet: self)
      options[:packet] = self
      header = klass.new(options)
      add_header(header, previous_header: prev)
      idx = headers.index(prev) + 1
      headers[idx, 0] = header
      header[:body] = nxt
      self
    end

    # Check if a protocol header is embedded in packet.
    # @example
    #   pkt = PacketGen.gen('IP').add('UDP')
    #   pkt.is?('IP')   #=> true
    #   pkt.is?('TCP')  #=> false
    # @return [Boolean]
    # @raise [ArgumentError] unknown protocol
    def is?(protocol)
      klass = check_protocol(protocol)
      headers.any?(klass)
    end

    # Recalculate all packet checksums
    # @return [void]
    def calc_checksum
      headers.reverse_each do |header|
        header.calc_checksum if header.respond_to?(:calc_checksum)
      end
    end

    # Recalculate all packet length fields
    # @return [void]
    def calc_length
      headers.reverse_each do |header|
        header.calc_length if header.respond_to?(:calc_length)
      end
    end

    # Recalculate all calculatable fields (for now: length and checksum)
    # @return [void]
    # @author LemonTree55
    def calc
      headers.reverse_each do |header|
        header.calc_length if header.respond_to?(:calc_length)
        header.calc_checksum if header.respond_to?(:calc_checksum)
      end
    end

    # Get packet body. If packet (i.e. last header) has no +:body+ field, return +nil+.
    # @return [Headerable,BinStruct::String,nil]
    def body
      last_header[:body] if last_header.respond_to?(:body)
    end

    # Set packet body
    # @param [String] str Binary string
    # @return [void]
    # @raise [Error] Packet (i.e. last header) has no +:body+ field.
    # @note To set a {Headerable} object, prefer #{<<}
    # @see #<<
    # @since 4.1.0 raise {Error} if no body on packet
    def body=(str)
      raise Error, 'no body in last headeré' unless last_header.respond_to?(:body)

      last_header.body = str
    end

    # Get binary string (i.e. binary string sent on or received from network).
    # @return [String]
    def to_s
      first_header.to_s
    end

    # Write packet to a PCapNG file on disk.
    # @param [String] filename
    # @return [Array] see return from {PcapNG::File#to_file}
    # @see File
    def to_f(filename)
      PcapNG::File.new.read_array([self]).to_f(filename)
    end
    alias write to_f

    # Send packet on wire. Use first header +#to_w+ method.
    # @param [String,nil] iface interface name. Default to first non-loopback interface
    # @param [Boolean] calc if +true+, call {#calc} on packet before sending it.
    # @param [Integer] number number of times to send the packets
    # @param [Integer,Float] interval time, in seconds, between sending 2 packets
    # @return [void]
    # @since 2.1.4 add `calc`, `number` and `interval` parameters
    # @since 3.0.0 +calc+ defaults to +true+
    def to_w(iface=nil, calc: true, number: 1, interval: 1)
      iface ||= PacketGen.default_iface

      if first_header.respond_to?(:to_w)
        self.calc if calc

        number.times do
          first_header.to_w(iface)
          sleep(interval) if number > 1
        end
      else
        type = first_header.protocol_name
        raise WireError, "don't known how to send a #{type} packet on wire"
      end
    end

    # Encapulate another packet in +self+
    # @param [Packet] other
    # @param [Boolean] parsing set to +true+ to not update last current header field
    #    from binding with first other's one. Use only when current header field
    #    has its value set accordingly.
    # @return [self] +self+ updated with new headers from +other+
    # @raise [BindingError] do not known how to encapsulate
    # @since 1.1.0
    # @example
    #   # Create a first IP packet
    #   ip1 = PacketGen::Packet.gen('IP', id: 1)
    #   # Create second IP packet, to encapsulate in first
    #   ip2 = PacketGen.gen('IP', id: 2)
    #   ip1.encapsulate(ip2)
    #   ip1.ip(2) == ip2.ip
    def encapsulate(other, parsing: false)
      other.headers.each_with_index do |h, i|
        add_header(h, parsing: i.positive? || parsing)
      end
    end

    # Remove headers from +self+
    # @param [Array<Header>] hdrs
    # @return [self] +self+ with some headers removed
    # @raise [FormatError] any headers not in +self+
    # @raise [BindingError] removed headers result in an unknown binding
    # @since 1.1.0
    # @example
    #  # IP/IP encapsulation
    #  pkt = PacketGen::Packet.gen('IP', id: 1).add('IP', id:2)
    #  # Remove outer IP header
    #  pkt.decapsulate(pkt.ip(1))
    #  pkt.ip.id #=> 2
    def decapsulate(*hdrs)
      hdrs.each do |hdr|
        prev_hdr = previous_header(hdr)
        next_hdr = next_header(hdr)
        headers.delete(hdr)
        add_header(next_hdr, previous_header: prev_hdr) if prev_hdr && next_hdr
      end
      invalidate_header_cache
      self
    rescue ArgumentError => e
      raise FormatError, e.message
    end

    # Parse a binary string and populate Packet from it.
    # @param [String] binary_str
    # @param [String,nil] first_header First protocol header name. +nil+ means discover it!
    # @return [self]
    # @raise [ParseError] +first_header+ is an unknown header
    # @raise [BindingError] unknwon binding between some headers
    def parse(binary_str, first_header: nil)
      headers.clear

      if first_header.nil?
        # No decoding forced for first header. Have to guess it!
        first_header = guess_first_header(binary_str)
        raise ParseError, "cannot identify first header in string: #{binary_str.inspect}" if first_header.nil?
      end

      add(first_header)
      headers[-1, 1] = last_header.read(binary_str)

      # Decode upper headers recursively
      decode_bottom_up
      self
    end

    # Get packet as a pretty formatted string.
    # @return [String]
    def inspect
      str = Inspect.dashed_line(self.class)
      headers.each do |header|
        str << header.inspect
      end
      str << Inspect.inspect_body(body)
    end

    # Check equality at binary level
    # @param [Packet] other
    # @return [Boolean]
    def ==(other)
      to_s == other.to_s
    end

    # +true+ if {#==} is +true+ with another packet, or if +other+ is a protocol name String, whose protocol is in Packet.
    # @param [Packet] other
    # @return [Boolean]
    # @since 3.1.2
    def ===(other)
      case other
      when PacketGen::Packet
        self == other
      when String
        is?(other)
      else
        false
      end
    end

    # Invert all possible attributes in packet to create a reply.
    # @return [self]
    # @note Only modify headers responding to +#reply!+.
    # @since 2.7.0
    def reply!
      headers.each do |header|
        header.reply! if header.respond_to?(:reply!)
      end
      self
    end

    # Forge a new packet from current one with all possible fields
    # inverted. The new packet may be a reply to current one.
    # @return [Packet]
    # @note Only modify headers responding to +#reply!+.
    # @since 2.7.0
    def reply
      pkt = dup
      pkt.reply!
    end

    # Append an already defined header to packet
    # @param [Headerable] header
    # @return [self]
    # @raise [ArgumentError] unknown protocol
    # @raise [BindingError] unknown binding
    # @example
    #  pkt = PacketGen.gen('Eth')
    #  # Add a new header from its type
    #  pkt.add('IP')
    #  # Add a new pre-generated header
    #  pkt << PacketGen::Header::TCP.new
    # @see #add
    # @since 4.1.0
    # @author LemonTree55
    def <<(header)
      add_header(header)
      self
    end

    private

    # Dup +@headers+ instance variable. Internally used by +#dup+ and +#clone+
    # @return [void]
    def initialize_copy(_other)
      @headers = headers.map(&:dup)
      headers.each do |header|
        add_magic_header_method(header)
      end
      invalidate_header_cache
    end

    # Give first header of packet
    # @return [Header::Base]
    def first_header
      headers.first
    end

    # Give last header of packet
    # @return [Header::Base]
    def last_header
      headers.last
    end

    # Give header index in packet
    # @param [Headerable] hdr
    # @return [Integer]
    # @raise [FormatError] +hdr+ not in packet
    def header_index(hdr)
      idx = headers.index(hdr)
      raise FormatError, 'header not in packet!' if idx.nil?

      idx
    end

    # Give header previous +hdr+ in packet
    # @param [Headerable] hdr
    # @return [Headerable,nil] May return +nil+ if +hdr+ is the first header in packet
    # @raise [FormatError] +hdr+ not in packet
    def previous_header(hdr)
      idx = header_index(hdr)
      idx.positive? ? headers[idx - 1] : nil
    end

    # Give header next +hdr+ in packet
    # @param [Headerable] hdr
    # @return [Headerable,nil] May return +nil+ if +hdr+ is the last header in packet
    # @raise [FormatError] +hdr+ not in packet
    def next_header(hdr)
      idx = header_index(hdr)
      (idx + 1) < headers.size ? headers[idx + 1] : nil
    end

    # @overload header(klass, layer=1)
    #  Get a header given its class and its layer (example: IP-in-IP encapsulation)
    #  @param [Class] klass
    #  @param [Integer] layer
    # @overload header(klass, options={})
    #  Get a header given its class, and set some attributes
    #  @param [String] klass
    #  @param [Hash] options attributes to set
    #  @raise [ArgumentError] unknown attribute
    # @return [Header::Base,nil]
    def header(klass, arg)
      layer = arg.is_a?(Integer) ? arg : 1
      header = find_header(klass, layer)
      return nil if header.nil?
      return header unless arg.is_a?(Hash)

      arg.each do |key, value|
        raise ArgumentError, "unknown #{key} attribute for #{klass}" unless header.respond_to?(:"#{key}=")

        header.send(:"#{key}=", value)
      end

      header
    end

    # Get header from cache, or find it in packet
    # @param [Class] klass
    # @param [Integer] layer
    # @return [Header::Base,nil]
    def find_header(klass, layer)
      header = fetch_header_from_cache(klass, layer)
      return header if header

      header = headers.select { |h| h.is_a?(klass) }[layer - 1]
      return nil if header.nil?

      add_header_to_cache(header, klass, layer)
      header
    end

    # check if protocol is known
    # @param [String] protocol
    # @raise [ArgumentError] unknown protocol
    def check_protocol(protocol)
      klass = Header.get_header_class_by_name(protocol)
      raise ArgumentError, "unknown #{protocol} protocol" if klass.nil?

      klass
    end

    # Add a header to packet
    # @param [Headerable] header
    # @param [Headerable] previous_header
    # @param [Boolean] parsing
    # @return [void]
    # @raise [BindingError]
    def add_header(header, previous_header: nil, parsing: false)
      invalidate_header_cache
      prev_header = previous_header || last_header
      add_to_previous_header(prev_header, header, parsing) if prev_header

      header.packet = self
      headers << header unless previous_header

      return if respond_to?(header.method_name)

      add_magic_header_method(header)
    end

    # Bind +header+ to +prev_header+.
    # @param [Headerable] prev_header
    # @param [Headerable] header
    # @param [Boolean] parsing
    # @return [void]
    # @raise [BindingError]
    def add_to_previous_header(prev_header, header, parsing)
      bindings = prev_header.class.known_headers[header.class] || prev_header.class.known_headers[header.class.superclass]
      raise BindingError.new(prev_header, header) if bindings.nil?

      bindings.set(prev_header) if !bindings.empty? && !parsing
      prev_header[:body] = header
    end

    # Add method to access +header+
    # @param [Header::Base] header
    # @return [void]
    def add_magic_header_method(header)
      self.instance_eval "def #{header.method_name}(arg=nil);" \
                         "header(#{header.class}, arg); end"
    end

    # Try to guess header from +binary_str+
    # @param [String] binary_str
    # @return [String,nil] header/protocol name, or nil if cannot be guessed
    def guess_first_header(binary_str)
      first_header = nil
      Header.all.each do |hklass|
        hdr = hklass.new(packet: self)
        # #read may return another object (more specific class)
        hdr = hdr.read(binary_str)
        # First header is found when, for one known header,
        # * +#parse?+ is true
        # * it exists a known binding with a upper header
        next unless hdr.parse?

        first_header = hklass.to_s.gsub(/.*::/, '') if search_upper_header(hdr)
        break unless first_header.nil?
      end
      first_header
    end

    # Decode packet bottom up
    # @return [void]
    def decode_bottom_up
      loop do
        last_known_hdr = last_header
        break if !last_known_hdr.respond_to?(:body) || last_known_hdr.body.empty?

        nh = search_upper_header(last_known_hdr)
        break if nh.nil?

        nheader = nh.new(packet: self)
        nheader = nheader.read(last_known_hdr.body)
        next unless nheader.parse?

        add_header(nheader, parsing: true)
        break if last_header == last_known_hdr
      end
    end

    # Search a upper header for +hdr+
    # @param [Header::Base] hdr
    # @return [void]
    # @yieldparam [Header::Base] found upper header
    def search_upper_header(hdr)
      hdr.class.known_headers.each do |nh, bindings|
        return nh if bindings.check?(hdr)
      end

      nil
    end

    def invalidate_header_cache
      return unless cache_headers

      @header_cache = {}
    end

    # Fetch header from cache if authorized
    # @param [Class] klass
    # @param [Integer] layer
    # @return [Header::Base,nil]
    def fetch_header_from_cache(klass, layer)
      @header_cache.fetch(klass, []).fetch(layer - 1, nil) if cache_headers
    end

    # Add header to cache if authorized
    # @param [Class] klass
    # @param [Integer] layer
    # @return [Header::Base,nil]
    def add_header_to_cache(header, klass, layer)
      return unless cache_headers

      @header_cache[klass] ||= []
      @header_cache[klass][layer - 1] = header
    end
  end
end

# rubocop:enable Metrics/ClassLength

require_relative 'headerable'
require_relative 'header'
