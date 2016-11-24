module PacketGen

  # An object of type {Packet} handles a network packet. This packet may contain
  # multiple protocol headers, starting from MAC layer or from Network (OSI) layer.
  #
  # Creating a packet is fairly simple:
  #  Packet.gen 'IP', src: '192.168.1.1', dst: '192.168.1.2'
  #
  # == Create a packet
  # Packets may be hand-made or parsed from a binary string:
  #  Packet.gen('IP', src: '192.168.1.1', dst: '192.168.1.2').add('UDP', sport: 45000, sport: 23)
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

    # Create a new Packet
    # @param [String] protocol base protocol for packet
    # @param [Hash] options specific options for +protocol+
    # @return [Packet]
    def self.gen(protocol, options={})
      self.new.add protocol, options
    end

    # Parse a binary string and generate a Packet from it.
    # @param [String] binary_str
    # @return [Packet]
    def self.parse(binary_str)
    end

    # Shortcut for {Packet.capture}
    # @param [String] iface interface name
    # @param [Hash] options capture options. See {Packet.capture}.
    # @yieldparam [Packet] packet
    # @return [Array<Packet>]
    def self.capture(iface, options={})
    end

    # Shortcut for {Packet.read}
    # @param [String] filename PcapNG file
    # @return [Array<Packet>]
    def self.read(filename)
    end

    # Shortcut for {Packet.write}
    # @param [String] filename
    # @param [Array<Packet>] packets packets to write
    # @return [void]
    def self.write(filename, packets)
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
        prev_header.body = header
        layer = prev_header.class.known_layers[klass]
        prev_header[layer.key] = layer.value
      end
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
  end
end

require_relative 'header'
