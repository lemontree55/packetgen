# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  # Capture packets from wire
  # @author Sylvain Daubert
  # @author Kent 'picat' Gruber
  class Capture
    # Default snaplen to use if :snaplen option not defined.
    DEFAULT_SNAPLEN = 0xffff

    private

    attr_reader :filter, :cap_thread

    public

    # Get captured packets.
    # @return [Array<Packets>]
    attr_reader :packets

    # Get captured packet raw data.
    # @return [Array<String>]
    attr_reader :raw_packets

    # Get interface name
    # @return [String]
    attr_reader :iface

    # @param [String] iface interface on which capture
    #    packets on. Default: Use default interface lookup. If no interface found,
    #    use loopback one.
    # @param [Integer] max maximum number of packets to capture.
    # @param [Integer] timeout maximum number of seconds before end
    #    of capture. Default: +nil+ (no timeout)
    # @param [String] filter bpf filter
    # @param [Boolean] promisc (default: +false+)
    # @param [Boolean] parse parse raw data to generate packets before
    #    yielding.  Default: +true+
    # @param [Integer] snaplen maximum number of bytes to capture for
    #    each packet.
    # @since 2.0.0 remove old 1.x API
    # @since 3.0.0 arguments are kwargs and nor more a hash
    def initialize(iface: nil, max: nil, timeout: nil, filter: nil, promisc: false, parse: true, snaplen: DEFAULT_SNAPLEN)
      @iface = iface || Interfacez.default || Interfacez.loopback

      @packets     = []
      @raw_packets = []
      set_options iface, max, timeout, filter, promisc, parse, snaplen
    end

    # Start capture
    # @see {#initialize} for parameters
    # @yieldparam [Packet,String] packet if a block is given, yield each
    #    captured packet (Packet or raw data String, depending on +:parse+ option)
    # @since 3.0.0 arguments are kwargs and nor more a hash
    def start(iface: nil, max: nil, timeout: nil, filter: nil, promisc: false, parse: true, snaplen: DEFAULT_SNAPLEN)
      set_options iface, max, timeout, filter, promisc, parse, snaplen

      pcap = PCAPRUB::Pcap.open_live(self.iface, @snaplen, @promisc, 1)
      set_filter_on pcap

      @cap_thread = Thread.new do
        pcap.each do |packet_data|
          raw_packets << packet_data
          if @parse
            packet = Packet.parse(packet_data)
            packets << packet
            yield packet if block_given?
          elsif block_given?
            yield packet_data
          end
          break if defined?(@max) && (raw_packets.size >= @max)
        end
      end
      cap_thread.join(@timeout)
    end

    # Stop capture. Should be used from another thread, as {#start} blocks.
    #
    # BEWARE: multiple capture should not be started in different threads. No effort
    # has been made to make Capture nor PacketGen thread-safe.
    # @return [void]
    def stop
      cap_thread.kill
    end

    private

    def set_options(iface, max, timeout, filter, promisc, parse, snaplen)
      @max = max if max
      @filter = filter unless filter.nil?
      @timeout = timeout unless timeout.nil?
      @promisc = promisc unless promisc.nil?
      @snaplen = snaplen unless snaplen.nil?
      @parse = parse unless parse.nil?
      @iface = iface unless iface.nil?
    end

    def set_filter_on(pcap)
      return if filter.nil? || filter.empty?

      pcap.setfilter filter
    end
  end
end
