# frozen_string_literal: true

require_relative 'spec_helper'
require 'tempfile'

module PacketGenTest1
  class TestHeader < PacketGen::Header::Base
  end
end

describe PacketGen do
  let(:file) { File.join(__dir__, 'pcapng', 'sample.pcapng') }

  describe '.gen' do
    it 'generate a Packet' do
      pkt = PacketGen.gen('IP', src: '192.168.1.1')
      expect(pkt.ip.src).to eq('192.168.1.1')
    end
  end

  describe '.parse' do
    before do
      @raw_pkts = PacketGen::PcapNG::File.new.read_packet_bytes(file)
    end

    it 'parse a packet from binary string' do
      pkt = nil
      expect { pkt = PacketGen.parse(@raw_pkts.first) }.not_to raise_error
      expect(pkt).to respond_to :eth
      expect(pkt).to respond_to :ip
      expect(pkt).to respond_to :udp
      expect(pkt.eth.dst).to eq('00:03:2f:1a:74:de')
      expect(pkt.udp.checksum).to eq(0x8bf8)

      expect { pkt = PacketGen.parse(@raw_pkts.first, first_header: 'Eth') }
        .not_to raise_error
    end
  end

  describe '.read' do
    it 'generates packets from a file' do
      ary = PacketGen.read(file)
      expect(ary).to be_a(Array)
      expect(ary).to all(be_a(PacketGen::Packet))
    end
  end

  describe '.write' do
    it 'writes packets to a file' do
      ary = PacketGen.read(file)
      write_file = Tempfile.new('pcapng')
      begin
        PacketGen.write(write_file.path, ary)
        expect(PacketGen.read(write_file.path)).to eq(ary)
      ensure
        write_file.close
        write_file.unlink
      end
    end
  end

  describe '.capture', :sudo do
    it 'captures packets' do
      yielded_packets = []
      packets = nil
      cap_thread = Thread.new do
        packets = PacketGen.capture(iface: 'lo', timeout: 1) { |pkt| yielded_packets << pkt }
      end
      sleep 0.1
      system 'ping -c 2 127.0.0.1 > /dev/null'
      cap_thread.join(0.5)
      expect(yielded_packets.size).to eq(packets.size)
      expect(yielded_packets).to eq(packets)
    end
  end

  describe '.header' do
    after(:all) do
      PacketGen::Header.remove_class PacketGenTest1::TestHeader
    end

    it 'generates a header object from given protocol name' do
      expect(PacketGen.header('Dot11::Data')).to be_a(PacketGen::Header::Dot11::Data)
    end

    it 'generates a header object from given protocol name, with options' do
      hdr = PacketGen.header('Dot11::Data', id: 0xfedc)
      expect(hdr).to be_a(PacketGen::Header::Dot11::Data)
      expect(hdr.id).to eq(0xfedc)
    end

    it 'generates a header object from given protocol name (plugin)' do
      PacketGen::Header.add_class PacketGenTest1::TestHeader
      expect(PacketGen.header('TestHeader')).to be_a(PacketGenTest1::TestHeader)
    end
  end
end
