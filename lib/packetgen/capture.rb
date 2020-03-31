# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require_relative 'pcaprub_wrapper'

module PacketGen
  # Capture packets from wire
  # @author Sylvain Daubert
  # @author Kent 'picat' Gruber
  class Capture
    private

    attr_reader :filter, :cap_thread, :snaplen, :promisc, :monitor

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
    # @param [Boolean] monitor enable or disable monitor mode on interface (if supported by +iface+).
    # @since 2.0.0 remove old 1.x API
    # @since 3.0.0 arguments are kwargs and no more a hash
    # @since 3.1.5 add monitor argument
    def initialize(iface: nil, max: nil, timeout: nil, filter: nil, promisc: false, parse: true, snaplen: nil, monitor: nil)
      @iface = iface || PacketGen.default_iface || PacketGen.loopback_iface

      @packets     = []
      @raw_packets = []
      set_options iface, max, timeout, filter, promisc, parse, snaplen, monitor
    end

    # Start capture
    # @see {#initialize} for parameters
    # @yieldparam [Packet,String] packet if a block is given, yield each
    #    captured packet (Packet or raw data String, depending on +:parse+ option)
    # @since 3.0.0 arguments are kwargs and no more a hash
    # @since 3.1.5 add monitor argument
    def start(iface: nil, max: nil, timeout: nil, filter: nil, promisc: false, parse: true, snaplen: nil, monitor: nil, &block)
      set_options iface, max, timeout, filter, promisc, parse, snaplen, monitor

      @cap_thread = Thread.new do
        PCAPRUBWrapper.capture(**capture_args) do |packet_data|
          add_packet(packet_data, &block)
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

    def set_options(iface, max, timeout, filter, promisc, parse, snaplen, monitor)
      @max = max if max
      @filter = filter unless filter.nil?
      @timeout = timeout unless timeout.nil?
      @promisc = promisc unless promisc.nil?
      @snaplen = snaplen unless snaplen.nil?
      @parse = parse unless parse.nil?
      @iface = iface unless iface.nil?
      @monitor = monitor unless monitor.nil?
    end

    def capture_args
      h = { iface: iface, filter: filter, monitor: monitor }
      h[:snaplen] = snaplen unless snaplen.nil?
      h[:promisc] = promisc unless promisc.nil?
      h
    end

    def filter_on(pcap)
      return if filter.nil? || filter.empty?

      PCAPRUBWrapper.filter_on(pcap: pcap, filter: filter)
    end

    def add_packet(data, &block)
      raw_packets << data
      if @parse
        packet = Packet.parse(data)
        packets << packet
        block&.call(packet)
      elsif block
        yield data
      end
    end
  end
end
