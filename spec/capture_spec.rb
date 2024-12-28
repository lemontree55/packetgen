# frozen_string_literal: true

require_relative 'spec_helper'

module PacketGen
  describe Capture do
    let(:iface) { Pcap.lookupdev }

    describe '#initialize' do
      it 'accepts no options' do
        cap = nil
        expect { cap = Capture.new }.not_to raise_error
        expect(cap).to be_a(Capture)
      end

      it 'accepts options' do
        options = { max: 12, timeout: 30, filter: 'ip', promisc: true, snaplen: 45, monitor: true }
        expect { Capture.new(**options) }.not_to raise_error
      end
    end

    describe '#start', :sudo do
      it 'captures packets and returns a array of Packet' do
        cap = capture(iface: 'lo') do
          ping('127.0.0.1', count: 3, interval: 0.2)
        end

        packets = cap.packets
        expect(packets).to be_a(Array)
        expect(packets.size).to be >= 6 # some packets may be send by system during test
        expect(packets).to all(be_a(Packet))
        expect(packets).to all(respond_to(:eth))
      end

      it 'captures unknown packets' do
        bin_str = PacketGen.gen('Eth', dst: 'ff:ff:ff:ff:ff:ff', ethertype: 42, body: (1..4).to_a.pack('C*')).to_s

        cap = capture(iface: 'lo') do
          unk_pack = UnknownPacket.new.parse(bin_str)
          Inject.inject(iface: 'lo', data: unk_pack)
        end

        packet = cap.packets.find { |pkt| pkt.is_a?(UnknownPacket) }
        expect(packet).not_to be_nil
        expect(packet.body).to eq(bin_str)
      end

      it 'capture packets until :timeout seconds' do
        cap = Capture.new(iface: 'lo')
        before = Time.now
        cap.start(timeout: 1)
        after = Time.now
        expect(after - before).to be < 2
      end

      it 'captures packets using a filter' do
        cap = capture(iface: 'lo', filter: 'ip dst 127.0.0.2') do
          system '(ping -c 1 127.0.0.1; ping -c 1 127.0.0.2) > /dev/null'
        end

        packets = cap.packets
        expect(packets.size).to eq(1)
        expect(packets.first.ip.src).to eq('127.0.0.1')
        expect(packets.first.ip.dst).to eq('127.0.0.2')
      end

      it 'captures raw packets with option parse: false' do
        cap = capture(iface: 'lo', parse: false) do
          ping('127.0.0.1', count: 1)
        end

        packets = cap.raw_packets
        expect(packets).to be_a(Array)
        expect(packets).to all(be_a(String))
      end

      it 'captures :max packets' do
        cap = capture(iface: 'lo', max: 2) do
          ping('127.0.0.1', count: 2, interval: 0.2)
        end

        packets = cap.packets
        expect(packets.size).to eq(2)
      end

      it 'yields captured packets' do
        yielded_packets = []
        cap = Capture.new(iface: 'lo', timeout: 3)
        cap_thread = Thread.new { cap.start { |pkt| yielded_packets << pkt } }
        sleep 0.1
        ping('127.0.0.1', count: 2)
        cap_thread.join(0.5)
        expect(cap.packets.size).to be >= 4
        expect(yielded_packets.size).to eq(cap.packets.size)
        expect(yielded_packets).to eq(cap.packets)
      end

      it 'yields captured raw packets' do
        yielded_packets = []
        cap = Capture.new(iface: 'lo', parse: false, timeout: 3)
        cap_thread = Thread.new { cap.start { |pkt| yielded_packets << pkt } }
        sleep 0.1
        ping('127.0.0.1', count: 2)
        cap_thread.join(0.5)
        expect(cap.raw_packets.size).to be >= 4
        expect(yielded_packets.size).to eq(cap.raw_packets.size)
        expect(yielded_packets).to eq(cap.raw_packets)
      end

      it 'yields packet timestamp' do
        timestamps = []
        cap = Capture.new(iface: 'lo', timeout: 3)
        cap_thread = Thread.new { cap.start { |_pkt, ts| timestamps << ts } }
        sleep 0.1
        ping('127.0.0.1', count: 1)
        cap_thread.join(0.5)
        expect(cap.packets.size).to be >= 2
        expect(timestamps.size).to eq(cap.packets.size)
        expect(timestamps).to all(be_a(Time))
      end

      it 'yields raw packet timestamp' do
        timestamps = []
        cap = Capture.new(iface: 'lo', parse: false, timeout: 3)
        cap_thread = Thread.new { cap.start { |_pkt, ts| timestamps << ts } }
        sleep 0.1
        ping('127.0.0.1', count: 1)
        cap_thread.join(0.5)
        expect(cap.raw_packets.size).to be >= 2
        expect(timestamps.size).to eq(cap.raw_packets.size)
        timestamps.each do |ts|
          expect(ts).to be_a(Time)
        end
      end
    end
  end
end
