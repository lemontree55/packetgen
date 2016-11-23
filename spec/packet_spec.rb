require_relative 'spec_helper'

module PacketGen

  describe Packet do

    describe '.gen' do
      it 'raises on unknown protocol' do
        expect { Packet.gen 'IPOT' }.to raise_error(ArgumentError)
      end

      it 'generates a packet with one header' do
        pkt = Packet.gen('IP')
        expect(pkt.headers.size).to eq(1)
        expect(pkt.headers.first).to be_a(Header::IP)
      end

      it 'generates a packet with good protocol' do
        pkt = Packet.gen('IP')
        expect(pkt.is? 'IP').to be(true)
      end

      it 'magically defines `protocol` method' do
        pkt = Packet.gen('IP')
        expect(pkt.respond_to? :ip).to be(true)
        expect(pkt.ip).to be_a(Header::IP)
      end

      it 'accepts options for given protocol' do
        pkt = Packet.gen('IP', src: '192.168.1.1')
        expect(pkt.ip.src).to eq('192.168.1.1')
      end
    end

    describe '#add' do
      before(:each) do
        @pkt = Packet.gen('IP')
      end

      it 'adds another protocol in packet' do
        @pkt.add 'IP'
        expect(@pkt.headers.size).to eq(2)
        expect(@pkt.headers[1]).to be_a(Header::IP)
      end

      it 'sets added protocol header as body of previous header' do
        2.times { @pkt.add 'IP' }
        expect(@pkt.ip(1).body).to eq(@pkt.ip(2))
        expect(@pkt.ip(2).body).to eq(@pkt.ip(3))
        expect(@pkt.ip(3).body).to be_empty
      end

      it 'sets protocol information in previous header' do
        expect(@pkt.ip.proto).to eq(0)
        @pkt.add 'IP'
        expect(@pkt.ip.proto).to eq(Header::IP.known_layers[Header::IP].value)
        expect(@pkt.ip(2).proto).to eq(0)
      end

      it 'raises on unknown protocol' do
        expect { @pkt.add 'IPOT' }.to raise_error(ArgumentError)
      end
    end

    describe '#is?' do
      before(:each) do
        @pkt = Packet.gen('IP')
      end

      it 'returns true for contained header type' do
        expect(@pkt.is? 'IP').to be(true)
      end

      it 'returns false for absent header type' do
        expect(@pkt.is? 'Eth').to be(true)
      end

      it 'raises on unknown protocol' do
        expect { @pkt.is? 'IPOT' }.to raise_error(ArgumentError)
      end
    end
  end
end
