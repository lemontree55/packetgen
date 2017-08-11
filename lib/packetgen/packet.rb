# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'pcaprub'

module PacketGen

  # An object of type {Packet} handles a network packet. This packet may contain
  # multiple protocol headers, starting from MAC layer or from Network (OSI) layer.
  #
  # Creating a packet is fairly simple:
  #  Packet.gen 'IP', src: '192.168.1.1', dst: '192.168.1.2'
  #
  # == Create a packet
  # Packets may be hand-made or parsed from a binary string:
  #  Packet.gen('IP', src: '192.168.1.1', dst: '192.168.1.2').add('UDP', sport: 45000, dport: 23)
  #  Packet.parse(binary_string)
  #
  # == Access packet information
  #  pkt = Packet.gen('IP').add('UDP')
  #  # read information
  #  pkt.udp.sport
  #  pkt.ip.ttl
  #  # set information
  #  pkt.udp.dport = 2323
  #  pkt.ip.ttl = 1
  #  pkt.ip(ttl: 1, id: 1234)
  #
  # == Save a packet to a file
  #  pkt.write('file.pcapng')
  #
  # == Get packets
  # Packets may be captured from wire:
  #  Packet.capture do |packet|
  #    do_some_stuffs
  #  end
  #  packets = Packet.capture(iface: 'eth0', max: 5)  # get 5 packets from eth0
  #
  # Packets may also be read from a file:
  #  packets = Packet.read(file.pcapng)
  #
  # == Save packets to a file
  #  Packet.write 'file.pcapng', packets
  #
  # @author Sylvain Daubert
  class Packet
    # @return [Array<Header::Base]
    attr_reader :headers

    # Create a new Packet
    # @param [String] protocol base protocol for packet
    # @param [Hash] options specific options for +protocol+
    # @return [Packet]
    def self.gen(protocol, options={})
      self.new.add protocol, options
    end

    # Parse a binary string and generate a Packet from it.
    #   # auto-detect first header
    #   Packet.parse str
    #   # force decoding a Ethernet header for first header
    #   Packet.parse str, first_header: 'Eth'
    # @param [String] binary_str
    # @param [String,nil] first_header First protocol header. +nil+ means discover it!
    # @return [Packet]
    # @raise [ArgumentError] +first_header+ is an unknown header
    def self.parse(binary_str, first_header: nil)
      new.parse binary_str, first_header: first_header
    end

    # Capture packets
    # @param [Hash] options capture options
    # @option options [String]  :iface interface on which capture
    #    packets on. Default: Use default interface lookup.
    # @option options [Integer] :max maximum number of packets to capture
    # @option options [Integer] :timeout maximum number of seconds before end
    #    of capture
    # @option options [String] :filter bpf filter
    # @option options [Boolean] :promiscuous
    # @yieldparam [Packet] packet if a block is given, yield each captured packet
    # @return [Array<Packet>] captured packet
    def self.capture(options={})
      capture = Capture.new(options)
      if block_given?
        capture.start { |packet| yield packet }
      else
        capture.start
      end
      capture.packets
    end

    # Read packets from +filename+.
    #
    # For more control, see {PcapNG::File} or {PCAPRUB::Pcap}.
    # @param [String] filename PcapNG or Pcap file.
    # @return [Array<Packet>]
    # @author Sylvain Daubert
    # @author Kent Gruber
    def self.read(filename)
      begin
        PcapNG::File.new.read_packets filename
      rescue => e
        raise ArgumentError, e unless File.extname(filename.downcase) == '.pcap'
        packets = []
        PCAPRUB::Pcap.open_offline(filename).each_packet do |packet|
          next unless packet = PacketGen.parse(packet.to_s)  
          packets << packet
        end
        packets
      end
    end

    # Write packets to +filename+
    #
    # For more options, see {PcapNG::File}.
    # @param [String] filename
    # @param [Array<Packet>] packets packets to write
    # @return [void]
    def self.write(filename, packets)
      pf = PcapNG::File.new
      pf.array_to_file packets
      pf.to_f filename
    end

    # @private
    def initialize
      @headers = []
    end

    # Add a protocol on packet stack
    # @param [String] protocol
    # @param [Hash] options protocol specific options
    # @return [self]
    # @raise [ArgumentError] unknown protocol
    def add(protocol, options={})
      klass = check_protocol(protocol)

      header = klass.new(options)
      add_header header
      self
    end

    # Check if a protocol header is embedded in packet
    # @return [Boolean]
    # @raise [ArgumentError] unknown protocol
    def is?(protocol)
      klass = check_protocol protocol
      @headers.any? { |h| h.is_a? klass }
    end

    # Recalculate all packet checksums
    # @return [void]
    def calc_checksum
      @headers.reverse.each do |header|
        header.calc_checksum if header.respond_to? :calc_checksum
      end
    end

    # Recalculate all packet length fields
    # @return [void]
    def calc_length
      @headers.each do |header|
        header.calc_length if header.respond_to? :calc_length
      end
    end

    # Recalculate all calculatable fields (for now: length and checksum)
    # @return [void]
    def calc
      calc_length
      calc_checksum
    end

    # Get packet body
    # @return [Types]
    def body
      @headers.last.body if @headers.last.respond_to? :body
    end

    # Set packet body
    # @param [String] str
    # @return [void]
    def body=(str)
      @headers.last.body = str
    end

    # Get binary string
    # @return [String]
    def to_s
      @headers.first.to_s
    end

    # Write a PCapNG file to disk.
    # @param [String] filename
    # @return [Array] see return from {PcapNG::File#to_file}
    # @see File
    def to_f(filename)
      File.new.array_to_file(filename: filename, array: [self])
    end
    alias :write :to_f

    # send packet on wire. Use first header +#to_w+ method.
    # @param [String] iface interface name. Default to first non-loopback interface
    # @return [void]
    def to_w(iface=nil)
      iface ||= PacketGen.default_iface
      if @headers.first.respond_to? :to_w
        @headers.first.to_w(iface)
      else
        type = @headers.first.protocol_name
        raise WireError, "don't known how to send a #{type} packet on wire"
      end
    end

    # Encapulate another packet in +self+
    # @param [Packet] other
    # @param [Boolean] parsing set to +true+ to not update last current header field
    #    from binding with first other's one. Use only when current heade field as
    #    its value set accordingly.
    # @return [self] +self+ with new headers from +other+
    # @since 1.1.0
    def encapsulate(other, parsing: false)
      other.headers.each_with_index do |h, i|
        add_header h, parsing: (i > 0) || parsing
      end
    end

    # Remove headers from +self+
    # @param [Array<Header>] headers
    # @return [self] +self+ with some headers removed
    # @raise [FormatError] any headers not in +self+
    # @raise [FormatError] removed headers result in an unknown binding
    # @since 1.1.0
    def decapsulate(*headers)
      headers.each do |header|
        idx = @headers.index(header)
        raise FormatError, 'header not in packet!' if idx.nil?

        prev_header = idx > 0 ? @headers[idx - 1] : nil
        next_header = (idx+1) < @headers.size ? @headers[idx + 1] : nil
        @headers.delete_at(idx)
        if prev_header and next_header
          add_header(next_header, previous_header: prev_header)
        end
      end
    rescue ArgumentError => ex
      raise FormatError, ex.message
    end

    # Parse a binary string and populate Packet from it.
    # @param [String] binary_str
    # @param [String,nil] first_header First protocol header. +nil+ means discover it!
    # @return [Packet] self
    # @raise [ArgumentError] +first_header+ is an unknown header
    def parse(binary_str, first_header: nil)
      @headers.clear

      if first_header.nil?
        # No decoding forced for first header. Have to guess it!
        first_header = guess_first_header(binary_str)
        if first_header.nil?
          raise ParseError, 'cannot identify first header in string'
        end
      end
      add first_header
      @headers[-1, 1] = @headers.last.read(binary_str)

      # Decode upper headers recursively
      decode_bottom_up
      self
    end

    # @return [String]
    def inspect
      str = Inspect.dashed_line(self.class)
      @headers.each do |header|
        str << header.inspect
      end
      str << Inspect.inspect_body(body)
    end

    # @param [Packet] other
    # @return [Boolean]
    def ==(other)
      to_s == other.to_s
    end

    private

    # Dup +@headers+ instance variable. Internally used by +#dup+ and +#clone+
    # @return [void]
    def initialize_copy(other)
      @headers = @headers.dup
    end

    # @overload header(klass, layer=1)
    #  @param [Class] klass
    #  @param [Integer] layer
    # @overload header(klass, options={})
    #  @param [String] klass
    #  @param [Hash] options
    #  @raise [ArgumentError] unknown option
    # @return [Header::Base]
    def header(klass, arg)
      headers = @headers.select { |h| h.is_a? klass }
      layer = arg.is_a?(Integer) ? arg : 1
      header = headers[layer - 1]

      if arg.is_a? Hash
        arg.each do |key, value|
          unless header.respond_to? "#{key}="
            raise ArgumentError, "unknown #{key} attribute for #{klass}"
          end
          header.send "#{key}=", value
        end
      end

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
    # @param [Header::Base] header
    # @param [Header::Base] previous_header
    # @param [Boolean] parsing
    # @return [void]
    def add_header(header, previous_header: nil, parsing: false)
      prev_header = previous_header || @headers.last
      if prev_header
        bindings = prev_header.class.known_headers[header.class]
        if bindings.nil?
          bindings = prev_header.class.known_headers[header.class.superclass]
          if bindings.nil?
            msg = "#{prev_header.class} knowns no layer association with #{header.protocol_name}. "
            msg << "Try #{prev_header.class}.bind_layer(#{header.class}, "
            msg << "#{prev_header.method_name}_proto_field: "
            msg << "value_for_#{header.method_name})"
            raise ArgumentError, msg
          end
        end
        bindings.set(prev_header) if !bindings.empty? and !parsing
        prev_header[:body] = header
      end
      header.packet = self
      @headers << header unless previous_header
      unless respond_to? header.method_name
        self.class.class_eval "def #{header.method_name}(arg=nil);" \
                              "header(#{header.class}, arg); end"
      end
    end

    def guess_first_header(binary_str)
      first_header = nil
      Header.all.each do |hklass|
        hdr = hklass.new
        # #read may return another object (more specific class)
        hdr = hdr.read(binary_str)
        # First header is found when:
        # * for one known header,
        # * it exists a known binding with a upper header
        search_header(hdr) do
          first_header = hklass.to_s.gsub(/.*::/, '')
        end
        break unless first_header.nil?
      end
      first_header
    end

    def decode_bottom_up
      decode_packet_bottom_up = true
      while decode_packet_bottom_up do
        last_known_hdr = @headers.last
        break unless last_known_hdr.respond_to? :body
        break if last_known_hdr.body.empty?
        search_header(last_known_hdr) do |nh|
          str = last_known_hdr.body
          nheader = nh.new
          nheader = nheader.read(str)
          add_header nheader, parsing: true
          nheader.dissect if nheader.respond_to? :dissect
        end
        decode_packet_bottom_up = (@headers.last != last_known_hdr)
      end
    end

    def search_header(hdr)
      hdr.class.known_headers.each do |nh, bindings|
        if bindings.check?(hdr) and hdr.parse?
          yield nh
          break
        end
      end
    end
  end
end

require_relative 'header'
