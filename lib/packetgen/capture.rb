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
    #    of capture. Default: +nil+ (no timeout)
    # @option options [String] :filter bpf filter
    # @option options [Boolean] :promiscuous (default: +false+)
    # @option options [Boolean] :parse parse raw data to generate packets before
    #    yielding.  Default: +true+
    # @option options [Integer] :snaplen maximum number of bytes to capture for
    #    each packet
    def initialize(iface, options={})
      @packets = []
      @raw_packets = []
      @iface = iface
      set_options options
    end

    # Start capture
    # @param [Hash] options complete see {#initialize}.
    # @yieldparam [Packet,String] packet if a block is given, yield each
    #    captured packet (Packet or raw data String, depending on +:parse+)
    def start(options={})
      set_options options
      @pcap = PCAPRUB::Pcap.open_live(@iface, @snaplen, @promisc, 1)
      set_filter

      @cap_thread = Thread.new do
        @pcap.each do |packet_data|
          @raw_packets << packet_data
          if @parse
            packet = Packet.parse(packet_data)
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
      @cap_thread.join(@timeout)
    end

    # Stop capture. Should be used from another thread, as {#start} blocs.
    #
    # BEWARE: multiple capture should not be started in different threads. No effort
    # has been made to make Capture nor PacketGen thread-safe.
    # @return [void]
    def stop
      @cap_thread.kill
    end

    private

    def set_options(options)
      @max = options[:max] if options[:max]
      @filter = options[:filter] if options[:filter]
      if options[:timeout]
        @timeout = options[:timeout]
      else
        @timeout ||= 0
      end
      if options[:promisc]
        @promisc = options[:promisc]
      else
        @promisc ||= false
      end
      if options[:snaplen]
        @snaplen = options[:snaplen]
      else
        @snaplen ||= DEFAULT_SNAPLEN
      end
      if options[:parse].nil?
        @parse = true if @parse.nil?
      else
        @parse = options[:parse]
      end
    end

    def set_filter
      return if @filter.nil?
      return if @filter.empty?
      @pcap.setfilter @filter
    end
  end
end