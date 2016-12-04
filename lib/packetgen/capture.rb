module PacketGen

  # Capture packets from wire
  # @author Sylvain Daubert
  class Capture

    # Default snaplen to use if :snaplen option not defined
    DEFAULT_SNAPLEN = 0xffff

    # Get captured packets
    # @return [Array<Packets>]
    attr_reader :packets

    # Get captured packet raw data
    # @return [Array<String>]
    attr_reader :raw_packets

    # @param [String] iface interface on which capture packets
    # @param [Hash] options
    # @option options [Integer] :max maximum number of packets to capture
    # @option options [Integer] :timeout maximum number of seconds before end
    #    of capture
    # @option options [String] :filter bpf filter
    # @option options [Boolean] :promiscuous (default: +false+)
    # @option options [Integer] :snaplen maximum number of bytes to capture for
    def initialize(iface, options={})
      @packets = []
      @raw_packets = []
      @iface = iface
      @max = options[:max]
      @timeout = options[:timeout] || 1
      @filter = options[:filter]
      @promisc = options[:promisc] || false
      @snaplen = options[:snaplen] || DEFAULT_SNAPLEN
      @parse = options[:parse].nil? ? true : options[:parse]
    end

    # Start capture
    # @param [Hash] options complete options from {#initialize}.
    # @option options [Integer] :max maximum number of packets to capture
    # @option options [String] :filter
    # @option options [Boolean] :parse parse raw data to generate packets before
    #    yielding.  Default: +true+
    # @yieldparam [Packet,String] packet_data if a block is given, yield each
    #    captured packet (Packet or raw data String, depending on +:parse+)
    def start(options={})
      @pcap = PCAPRUB::Pcap.open_live(@iface, @snaplen, @promisc, @timeout)
      set_filter
      @pcap.each do |packet_data|
        p packet_data
        @raw_packets << packet_data
        if @parse
          packet = Packet.parse(packet_data)
          p packet
          @packets << packet
          yield packet if block_given?
        else
          yield packet_data if block_given?
        end
        if @max
          break if @raw_packets.size >= @max
        end
      end
    end

    private

    def set_filter
      return if @filter.nil?
      return if @filter.empty?
      @pcap.set_filter @filter
    end
  end
end
