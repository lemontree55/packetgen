# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen

  # Capture packets from wire
  # @author Sylvain Daubert
  # @author Kent 'picat' Gruber
  class Capture

    # Default snaplen to use if :snaplen option not defined.
    DEFAULT_SNAPLEN = 0xffff
    
    # Default snaplen to use if :timeout option not defined.
    DEFAULT_TIMEOUT = 1

    # Get captured packets.
    # @return [Array<Packets>]
    attr_reader :packets

    # Get captured packet raw data.
    # @return [Array<String>]
    attr_reader :raw_packets

    # Get interface name
    # @return [String]
    attr_reader :iface

    # @overload initialize(iface=Pcap.lookupdev, options={})
    #  @param [String] iface interface on which capture packets
    #  @param [Hash] options
    #  @option options [Integer] :max maximum number of packets to capture.
    #  @option options [Integer] :timeout maximum number of seconds before end
    #     of capture. Default: +nil+ (no timeout)
    #  @option options [String] :filter bpf filter
    #  @option options [Boolean] :promiscuous (default: +false+)
    #  @option options [Boolean] :parse parse raw data to generate packets before
    #     yielding.  Default: +true+
    #  @option options [Integer] :snaplen maximum number of bytes to capture for
    #     each packet.
    # @overload initialize(options={})
    #  @param [Hash] options
    #  @option options [String]  :iface interface on which capture
    #     packets on. Default: Use default interface lookup. If no interface found,
    #     use loopback one.
    #  @option options [Integer] :max maximum number of packets to capture.
    #  @option options [Integer] :timeout maximum number of seconds before end
    #     of capture. Default: +nil+ (no timeout)
    #  @option options [String] :filter bpf filter
    #  @option options [Boolean] :promiscuous (default: +false+)
    #  @option options [Boolean] :parse parse raw data to generate packets before
    #     yielding.  Default: +true+
    #  @option options [Integer] :snaplen maximum number of bytes to capture for
    #     each packet.
    def initialize(iface_or_options={}, options={})
      begin
        @iface = Pcap.lookupdev
      rescue PCAPRUB::BindingError
        @iface = 'lo'
      end

      case iface_or_options
      when Hash
        options = iface_or_options
      else
        warn "[deprecation] use of PacketGen::Capture#initialize with iface name as\n" \
             "              first argument is deprecated. Instead, use:\n" \
             '              PacketGen::Capture.new(iface: \'name\').'
        @iface = iface_or_options.to_s
      end

      @packets     = []
      @raw_packets = []
      @promisc = false
      @snaplen = DEFAULT_SNAPLEN
      @timeout = DEFAULT_TIMEOUT
      @parse = true
      set_options options
    end

    # Start capture
    # @param [Hash] options complete see {#initialize}.
    # @yieldparam [Packet,String] packet if a block is given, yield each
    #    captured packet (Packet or raw data String, depending on +:parse+ option)
    def start(options={})
      set_options options
      @pcap = PCAPRUB::Pcap.open_live(@iface, @snaplen, @promisc, @timeout)
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
          break if @max and @raw_packets.size >= @max
        end
      end
      @cap_thread.join(@timeout)
    end

    # Stop capture. Should be used from another thread, as {#start} blocks.
    #
    # BEWARE: multiple capture should not be started in different threads. No effort
    # has been made to make Capture nor PacketGen thread-safe.
    # @return [void]
    def stop
      @cap_thread.kill
    end

    private

    def set_options(options)
      @max     = options[:max]     if options[:max]
      @filter  = options[:filter]  if options[:filter]
      @timeout = options[:timeout] if options[:timeout]
      @promisc = options[:promisc] if options.has_key? :promisc
      @snaplen = options[:snaplen] if options[:snaplen]
      @parse   = options[:parse]   if options.has_key? :parse
      @iface   = options[:iface]   if options[:iface]
    end

    def set_filter
      return if @filter.nil?
      return if @filter.empty?
      @pcap.setfilter @filter
    end
  end
end
