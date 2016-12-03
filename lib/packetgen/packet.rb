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
  #  Packet.capture('eth0') do |packet|
  #    do_some_stuffs
  #  end
  #  packets = Packet.capture('eth0', max: 5)  # get 5 packets
  #
  # Packets may also be read from a file:
  #  packets = Packet.read(file.pcapng)
  #
  # == Save packets to a file
  #  Packet.write 'file.pcapng', packets
  class Packet
    # @return [Array<Header::Base]
    attr_reader :headers

    # @private maximum number of characters on a line for INSPECT
    INSPECT_MAX_WIDTH = 70

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
      pkt = new

      if first_header.nil?
        # No decoding forced for first header. Have to guess it!
        Header.all.each do |hklass|
          hdr = hklass.new
          hdr.read binary_str
          # First header is found when:
          # * for one known header,
          # * it exists a known binding with a upper header
          hklass.known_headers.each do |nh, binding|
            if hdr.send(binding.key) == binding.value
              first_header = hklass.to_s.gsub(/.*::/, '')
              break
            end
          end
          break unless first_header.nil?
        end
        if first_header.nil?
          raise ParseError, 'cannot identify first header in string'
        end
      end

      pkt.add(first_header)
      pkt.headers.last.read binary_str

      # Decode upper headers recursively
      decode_packet_bottom_up = true
      while decode_packet_bottom_up do
        last_known_hdr = pkt.headers.last
        last_known_hdr.class.known_headers.each do |nh, binding|
          if last_known_hdr.send(binding.key) == binding.value
            str = last_known_hdr.body
            pkt.add nh.to_s.gsub(/.*::/, '')
            pkt.headers.last.read str
            break
          end
        end
        decode_packet_bottom_up = (pkt.headers.last != last_known_hdr)
      end

      pkt
    end

    # Capture packets from +iface+
    # @param [String] iface interface name
    # @param [Hash] options capture options
    # @option options [Integer] :max maximum number of packets to capture
    # @option options [Integer] :timeout maximum number of seconds before end
    #    of capture
    # @option options [String] :filter bpf filter
    # @yieldparam [Packet] packet if a block is given, yield each captured packet
    # @return [Array<Packet>] captured packet
    def self.capture(iface, options={})
    end

    # Read packets from +filename+.
    #
    # For more control, see {PcapNG::File}.
    # @param [String] filename PcapNG file
    # @return [Array<Packet>]
    def self.read(filename)
      PcapNG::File.new.read_packets filename
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
      prev_header = @headers.last
      if prev_header
        binding = prev_header.class.known_headers[klass]
        if binding.nil?
          msg = "#{prev_header.class} knowns no layer association with #{protocol}. "
          msg << "Try #{prev_header.class}.bind_layer(PacketGen::Header::#{protocol}, "
          msg << "#{prev_header.class.to_s.gsub(/(.*)::/, '').downcase}_proto_field: "
          msg << "value_for_#{protocol.downcase})"
          raise ArgumentError, msg
        end
        prev_header[binding.key].read binding.value
        prev_header.body = header
      end
      header.packet = self
      @headers << header
      unless respond_to? protocol.downcase
        self.class.class_eval "def #{protocol.downcase}(arg=nil);" \
                              "header('#{protocol}', arg); end"
      end
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
    def calc_sum
      @headers.reverse.each do |header|
        header.calc_sum if header.respond_to? :calc_sum
      end
    end

    # Recalculate all packet length fields
    # @return [void]
    def calc_length
      @headers.each do |header|
        header.calc_length if header.respond_to? :calc_length
      end
    end

    # Get packet body
    # @return [StructFu]
    def body
      @headers.last.body
    end

    # Set packet body
    # @param [String]
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

    # send packet on wire. Use first header +#to_w+ method.
    # @param [String] iface interface name. Default to first non-loopback interface
    # @return [void]
    def to_w(iface=nil)
      iface ||= PacketGen.default_iface
      if @headers.first.respond_to? :to_w
        @headers.first.to_w(iface)
      else
        type = @headers.first.class.to_s.gsub(/.*::/, '')
        raise WireError, "don't known how to send a #{type} packet on wire"
      end
    end

    # @return [String]
    def inspect
      str = dashed_line(self.class)
      @headers.each do |header|
        str << dashed_line(header.class, 2)
        header.to_h.each do |attr, value|
          next if attr == :body
          str << inspect_line(attr, value, 2)
        end
      end
      str << inspect_body
    end

    # @param [Packet] other
    # @return [Boolean]
    def ==(other)
      to_s == other.to_s
    end

    private

    # @overload header(protocol, layer=1)
    #  @param [String] protocol
    #  @param [Integer] layer
    # @overload header(protocol, options)
    #  @param [String] protocol
    #  @param [Hash] options
    # @return [Header::Base]
    # @raise [ArgumentError] unknown protocol
    def header(protocol, arg)
      klass = check_protocol protocol

      headers = @headers.select { |h| h.is_a? klass }
      layer = arg.is_a?(Integer) ? arg : 1
      header = headers[layer - 1]

      if arg.is_a? Hash
        arg.each do |key, value|
          unless header.respond_to? "#{key}="
            raise ArgumentError, "unknown #{key} attribute for #{header.class}"
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
      unless Header.const_defined? protocol
        raise ArgumentError, "unknown #{protocol} protocol"
      end
      klass = Header.const_get(protocol)
      raise ArgumentError, "unknown #{protocol} protocol" unless klass.is_a? Class
      klass
    end

    def dashed_line(name, level=1)
      str = '--' * level << " #{name} "
      str << '-' * (INSPECT_MAX_WIDTH - str.length) << "\n"
    end

    def inspect_line(attr, value, level=1)
      str = '  ' + '  ' * level
      val = if value.is_a? StructFu::Int
              sz = value.to_s.size
              "%-10s (0x%0#{2*sz}x)" % [value.to_i, value.to_i]
            elsif value.respond_to? :to_x
              value.to_x
            else
              value.to_s
            end
      str << "%7s %10s: %s" % [value.class.to_s.sub(/.*::/, ''), attr, val]
      str << "\n"
    end

    def inspect_body
      str = dashed_line('Body', 2)
      str << (0..15).to_a.map { |v| " %02d" % v}.join << "\n"
      str << '-' * INSPECT_MAX_WIDTH << "\n"
      if body.size > 0
        (body.size / 16 + 1).times do |i|
          octets = body.to_s[i*16, 16].unpack('C*')
          o_str = octets.map { |v| " %02x" % v}.join
          str << o_str
          str << ' ' * (3*16 - o_str.size) unless o_str.size >= 3*16
          str << '  ' << octets.map { |v| v < 128 && v > 13 ? v.chr : '.' }.join
          str << "\n"
        end
      end
      str << '-' * INSPECT_MAX_WIDTH << "\n"
    end
  end
end

require_relative 'header'
