require_relative 'spec_helper'
require 'tempfile'

module PacketGen
  describe UnknownPacket do
    before(:each) do
      @bin_str = Packet.gen('Eth', ethertype: 42, body: (1..4).to_a.pack('C*')).to_s
      @pkt = UnknownPacket.new
      @pkt.body = @bin_str
    end

    it '#headers is always emptu' do
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
      before(:each) { @write_file = Tempfile.new('unknown_packet') }
      after(:each) { @write_file.close; @write_file.unlink }

      it 'writes packet as a PcapNG file' do
        @pkt.to_f(@write_file.path)

        pkt2 = PacketGen.read(@write_file.path).first
        expect(@pkt).to eq(pkt2)
      end
    end
  end
end
