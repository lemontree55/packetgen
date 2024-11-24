# frozen_string_literal: true

require_relative 'spec_helper'
require 'tempfile'

module PacketGen
  describe UnknownPacket do
    before do
      @bin_str = Packet.gen('Eth', ethertype: 42, body: (1..4).to_a.pack('C*')).to_s
      @pkt = UnknownPacket.new
      @pkt.body = @bin_str
    end

    it '#headers is always empty' do
      expect(@pkt.headers).to be_a(Array)
      expect(@pkt.headers).to be_empty
    end

    it '#body return binary string' do
      expect(@pkt.body).to eq(@bin_str)
    end

    it '#is? always returns false' do
      expect(@pkt.is?('IP')).to be(false)
      expect(@pkt.is?('Eth')).to be(false)
    end

    describe '#to_f' do
      before { @write_file = Tempfile.new('unknown_packet') }

      after do
        @write_file.close
        @write_file.unlink
      end

      it 'writes packet as a PcapNG file' do
        @pkt.to_f(@write_file.path)

        pkt2 = PacketGen.read(@write_file.path).first
        expect(@pkt).to eq(pkt2)
      end
    end

    describe '#==' do
      it 'returns true if #to_s is the same' do
        other_pkt = PacketGen.parse(@pkt.to_s, first_header: 'Eth')
        expect(other_pkt).to be_a(Packet)
        expect(@pkt == other_pkt.to_s).to be(true)
        expect(@pkt == other_pkt).to be(true)
      end

      it 'returns false if #to_s is not equal' do
        expect(@pkt == '12345').to be(false)
      end
    end

    describe '#inspect' do
      it 'returns a String' do
        expect(@pkt.inspect).to be_a(String)
      end
    end

    describe '#===' do
      it 'returns true if other is an Unknown packet with the same content' do
        other_pkt = @pkt.dup
        expect(@pkt === other_pkt).to be(true)
      end

      it 'returns fals if other is not an unknown packet' do
        other_pkt = PacketGen.parse(@pkt.to_s, first_header: 'Eth')
        expect(other_pkt).to be_a(Packet)
        expect(@pkt === other_pkt.to_s).to be(false)
        expect(@pkt === other_pkt).to be(false)
      end
    end
  end
end
