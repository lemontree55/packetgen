# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'thread'

module PacketGen
  module Utils

    # @note This class is provided for test purpose.
    # Utility class to make ARP spoofing.
    #   spoofer = PacketGen::Utils::ARPSpoofer.new
    #   # start an ARP spoof: send forged ARP packets to target to spoof spoofed_ip
    #   spoofer.start target_ip, spoofed_ip
    #   # start another ARP spoof. Say to target2 spoofed_ip has given MAC address
    #   spoofer.start target2_ip, spoofed_ip, mac: '00:00:00:00:00:01'
    #   # stop spoofing on target2
    #   spoofer.stop target2_ip
    #   # stop all spoofings
    #   spoofer.stop_all
    # @author Sylvain Daubert
    # @since 2.1.3
    class ARPSpoofer

      # @param [Integer,Float,nil] timeout spoof will happen for this amount
      #  of time
      # @param [Integer,Float] interval time between 2 ARP packets
      # @param [String,nil] iface network interface on which do spoofing.
      #  Defaults to {PacketGen.default_iface}
      def initialize(timeout: nil, interval: 1.0, iface: nil)
        @timeout = timeout
        @timeout = @timeout.to_f if @timeout
        @interval = interval
        @iface = iface || PacketGen.default_iface
        @targets = {}
        @arp_packets = {}
        @spoof_thread = nil
        @queue = Queue.new
      end

      # Add a target to spoofer, without starting attack. Spoofing should
      # be enabled with {#start_all}.
      # @param [String] target_ip target IP address
      # @param [String] spoofed_ip spoofed IP address
      # @param [Hash] options
      # @option options [String] :mac attacker's MAC address. Defaults to
      #  local MAC address.
      # @option options [String] :target_mac target MAC address. If not given,
      #  an ARP request is made to get it.
      # @return [void]
      def add(target_ip, spoofed_ip, options={})
        @targets[target_ip] = options.merge({spoofed_ip: spoofed_ip, active: false})
      end

      # Remove target from spoofer.
      # @param [String] target_ip target IP address
      # @return [void]
      def remove(target_ip)
        @targets.delete target_ip
        @arp_packets.delete target_ip
      end

      # Get registered targets (all targets, registered with {#add} and {#start})
      # @return [Array<String>] list of target IP addresses
      def registered_targets
        @targets.keys
      end

      # Get active targets (registered with {#start}, or all after using
      # {#start_all})
      # @return [Array<String>] list of target IP addresses
      def active_targets
        @arp_packets.keys
      end

      # Start spoofing on given target
      # @param [String] target_ip target IP address
      # @param [String] spoofed_ip spoofed IP address
      # @param [Hash] options
      # @option options [String] :mac attacker's MAC address. Defaults to
      #  local MAC address.
      # @option options [String] :target_mac target MAC address. If not given,
      #  an ARP request is made to get it.
      # @return [void]
      def start(target_ip, spoofed_ip, options={})
        add target_ip, spoofed_ip, options
        activate target_ip
      end

      # Stop spoofing on given target
      # @param [String] target_ip target IP address
      # @return [void]
      def stop(target_ip)
        deactivate target_ip
        remove target_ip
      end

      # Start spoofing on all targets added with {#add}.
      # @return [void]
      def start_all
        @targets.each do |target_ip, _|
          activate target_ip
        end
      end
      
      # Stop spoofing on all targets.
      # @return [void]
      def stop_all
        @targets.each do |target_ip, _|
          deactivate target_ip
        end
      end

      # Say if spoofing on given target is active or not
      # @param [String] target_ip target IP address
      # @return [Boolean,nil]
      def active?(target_ip)
        if @targets.has_key?(target_ip)
          @targets[target_ip][:active]
        else
          nil
        end
      end

      # Wait for spoofing to finish. Wait forever if no +timeout+ options
      # was set on {#initialize}.
      def wait
        @spoof_thread.join
      end

      private

      # Activate spoofing for given target
      # @param [String] target_ip
      # @return [void]
      def activate(target_ip)
        @arp_packets[target_ip] = make_arp_packet(target_ip)
        @queue << @arp_packets.values
        unless @spoof_thread
          create_spoof_thread
        end
        @targets[target_ip][:active] = true
      end
      
      # Create spoof thread
      def create_spoof_thread
        @spoof_thread = Thread.new(@queue, @iface, @timeout, @interval) do |queue, iface, timeout, interval|
          while timeout.nil? or timeout > 0.0 do
            packets = queue.pop unless queue.empty?
            send_packets_on_wire packets
            timeout -= interval if timeout
            sleep interval
          end
        end
      end

      # send packets on wire
      def send_packets_on_wire(packets)
        packets.each { |pkt| pkt.to_w(iface) }
      end

      # Deactivate spoofing for given target
      # @param [String] target_ip
      # @return [void]
      def deactivate(target_ip)
        @arp_packets.delete target_ip
        if @arp_packets.empty?
          @spoof_thread.kill
          @spoof_thread = nil
        else
          @queue << @arp_packets.values
        end
        @targets[target_ip][:active] = false
      end

      # Create ARP packet to spoof given target
      # @param [String] target_ip
      # @return [Packet]
      def make_arp_packet(target_ip)
        params = @targets[target_ip]
        mac = params[:mac] || Config.instance.hwaddr(@iface)

        target_mac = params[:target_mac] || Utils.arp(target_ip)

        Packet.gen('Eth', dst: target_mac, src: mac).
               add('ARP', op: 'reply', sha: mac, spa: params[:spoofed_ip],
                   tha: target_mac, tpa: target_ip)
      end
    end
  end
end
