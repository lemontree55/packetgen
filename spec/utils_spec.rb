require 'packetgen/utils'
require_relative 'spec_helper'

ARP_OUTPUT = """? (192.168.1.1) at 00:01:02:03:04:05 [ether] on eth0
? (192.168.1.2) at 00:11:22:33:44:55 on wlan0
"""

IP_OUTPUT = """192.168.1.1 dev wlp4s0 lladdr 05:04:03:02:01:00 REACHABLE
192.168.1.2 dev ens33 lladdr 55:44:33:22:11:00 REACHABLE
"""

def double_config
  config = class_double("PacketGen::Config").as_stubbed_const
  config_inst = instance_double(PacketGen::Config)
  allow(config).to receive(:instance).and_return(config_inst)

  [config, config_inst]
end

def double_capture_class
  capture = class_double("PacketGen::Capture").as_stubbed_const
  capture_inst = instance_double(PacketGen::Capture)
  expect(capture).to receive(:new).and_return(capture_inst)

  [capture, capture_inst]
end

def double_pcaprubwrapper_module
  class_double("PacketGen::PCAPRUBWrapper").as_stubbed_const
end

def double_arp_spoof_class
  klass_dbl = class_double("PacketGen::Utils::ARPSpoofer").as_stubbed_const
  inst_dbl = instance_double(PacketGen::Utils::ARPSpoofer)
  expect(klass_dbl).to receive(:new).and_return(inst_dbl)

  [klass_dbl, inst_dbl]
end

module PacketGen
  describe Utils do
    it ".cache_from_arp_command ets ARP cache from arp command" do
      cache = Utils.cache_from_arp_command(ARP_OUTPUT)
      expect(cache.size).to eq(2)
      expect(cache['192.168.1.1']).to eq(['00:01:02:03:04:05', 'eth0'])
      expect(cache['192.168.1.2']).to eq(['00:11:22:33:44:55', 'wlan0'])
    end

    it ".cache_from_ip_command gets ARP cache from ip neigh command" do
      cache = Utils.cache_from_ip_command(IP_OUTPUT)
      expect(cache.size).to eq(2)
      expect(cache['192.168.1.1']).to eq(['05:04:03:02:01:00', 'wlp4s0'])
      expect(cache['192.168.1.2']).to eq(['55:44:33:22:11:00', 'ens33'])
    end

    it ".arp returns a IP addrdess from a MAC one (no_cache: true)" do
      _config, config_inst = double_config
      _capture, capture_inst = double_capture_class
      inject = double_pcaprubwrapper_module

      my_mac = '00:01:02:03:04:05'
      my_ip = '172.16.0.23'
      target_mac = '05:04:03:02:01:00'
      target_ip = '172.16.0.1'
      reply = PacketGen.gen('Eth', dst: my_mac, src: target_mac)
                       .add('ARP', tha: my_mac, tpa: my_ip, spa: target_ip, sha: target_mac)

      allow(config_inst).to receive(:hwaddr).and_return(my_mac)
      allow(config_inst).to receive(:ipaddr).and_return(my_ip)

      expected_pkt = PacketGen.gen('Eth', dst: 'ff:ff:ff:ff:ff:ff', src: my_mac)
                              .add('ARP', sha: my_mac, spa: my_ip, tpa: target_ip)
      expect(capture_inst).to receive(:start)
      expect(capture_inst).to receive(:packets).and_return([reply])
      expect(capture_inst).to receive(:packets).and_return([reply])
      expect(inject).to receive(:inject).with(iface: 'iface0', data: expected_pkt.to_s)

      mac = Utils.arp(target_ip, iface: 'iface0', no_cache: true)
      expect(mac).to eq(target_mac)
    end

    it '.arp_spoof creates and start an ARP spoofer' do
      target_ip = '10.0.0.1'
      spoofed_ip = '10.0.0.254'
      _arp_spoofer, arp_spoofer_inst = double_arp_spoof_class

      expect(arp_spoofer_inst).to receive(:start).with(target_ip, spoofed_ip, mac: nil)
      expect(arp_spoofer_inst).to receive(:wait)

      Utils.arp_spoof(target_ip, spoofed_ip)
    end

    it '.mitm starts a MITM attack' do
      my_ip = '172.16.16.1'
      my_mac = '00:7f:7f:7f:7f:7f'
      target1 = '172.16.16.16'
      mac1 = '00:01:02:03:04:05'
      target2 = '172.16.16.166'
      mac2 = '00:11:22:33:44:55'

      other = { mac: '42:42:42:42:42:42', ip: '42.42.42.42' }

      pkt12 = Packet.gen('Eth', src: mac1, dst: mac2).add('IP', id: 1, src: target1, dst: target2)
      pkt21 = Packet.gen('Eth', src: mac2, dst: mac1).add('IP', id: 1, src: target2, dst: target1)
      pkt1other = Packet.gen('Eth', src: mac1, dst: other[:mac]).add('IP', id: 1, src: target1, dst: other[:ip])
      pktother1 = Packet.gen('Eth', src: other[:mac], dst: mac1).add('IP', id: 1, src: other[:ip], dst: target1)

      spoofed_pkt12 = Packet.gen('Eth', src: my_mac, dst: mac2).add('IP', id: 1, src: target1, dst: target2, checksum: 531)
      spoofed_pkt21 = Packet.gen('Eth', src: my_mac, dst: mac1).add('IP', id: 1, src: target2, dst: target1, checksum: 531)
      spoofed_pkt1other = Packet.gen('Eth', src: my_mac, dst: mac2).add('IP', id: 1, src: target1, dst: other[:ip], checksum: 0x6a75)
      spoofed_pktother1 = Packet.gen('Eth', src: my_mac, dst: mac1).add('IP', id: 1, src: other[:ip], dst: target1, checksum: 0x6a75)

      _config, config_inst = double_config
      _arp_spoofer, arp_spoofer_inst = double_arp_spoof_class
      arp = class_double('PacketGen::Utils')
      _capture, capture_inst = double_capture_class
      inject = double_pcaprubwrapper_module

      expect(arp_spoofer_inst).to receive(:add).with(target1, target2, {iface: 'iface0'})
      expect(arp_spoofer_inst).to receive(:add).with(target2, target1, {iface: 'iface0'})
      expect(config_inst).to receive(:hwaddr).and_return(my_mac)
      expect(config_inst).to receive(:ipaddr).and_return({'iface0' => my_ip})
      expect(arp_spoofer_inst).to receive(:start_all)
      allow(Utils).to receive(:arp).with(target1).and_return(mac1)
      allow(Utils).to receive(:arp).with(target2).and_return(mac2)
      expect(capture_inst).to receive(:start).and_yield(pkt12)
                                             .and_yield(pkt21)
                                             .and_yield(pkt1other)
                                             .and_yield(pktother1)
      expect(capture_inst).to receive(:iface).exactly(4).times.and_return('iface0')
      expect(inject).to receive(:inject).with(iface: 'iface0', data: spoofed_pkt12.to_s)
      expect(inject).to receive(:inject).with(iface: 'iface0', data: spoofed_pkt21.to_s)
      expect(inject).to receive(:inject).with(iface: 'iface0', data: spoofed_pkt1other.to_s)
      expect(inject).to receive(:inject).with(iface: 'iface0', data: spoofed_pktother1.to_s)
      expect(arp_spoofer_inst).to receive(:stop_all)

      Utils.mitm(target1, target2, iface: 'iface0') { |pkt| pkt }
    end
  end
end