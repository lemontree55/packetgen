require_relative 'spec_helper'

module PacketGen
  # Define fake header class for tests
  module Header
    class FakeHeader < Struct.new(:field); extend Header::HeaderClassMethods; end
  end

  describe Packet do

    describe '.gen' do
      before(:each) do
        @pkt = Packet.gen('IP')
     end

      it 'raises on unknown protocol' do
        expect { Packet.gen 'IPOT' }.to raise_error(ArgumentError)
      end

      it 'generates a packet with one header' do
        expect(@pkt.headers.size).to eq(1)
        expect(@pkt.headers.first).to be_a(Header::IP)
      end

      it 'generates a packet with good protocol' do
        expect(@pkt.is? 'IP').to be(true)
      end

      it 'accepts options for given protocol' do
        pkt = Packet.gen('IP', src: '192.168.1.1')
        expect(pkt.ip.src).to eq('192.168.1.1')
      end

      it 'magically defines `protocol` method' do
        expect(@pkt.respond_to? :ip).to be(true)
        expect(@pkt.ip).to be_a(Header::IP)
      end

      it 'magic methods accept arguments' do
        @pkt.ip(src: '192.168.1.1', dst: '192.168.1.127')
        expect(@pkt.ip.src).to eq('192.168.1.1')
        expect(@pkt.ip.dst).to eq('192.168.1.127')
      end

      it 'magic methods raise on unknown attribute' do
        attr = :unknown_attr
        expect { @pkt.ip(attr => nil) }.to raise_error(ArgumentError).
                                            with_message(/unknown #{attr} attribute/)
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

      it 'raises on unknown association' do
        expect { @pkt.add 'FakeHeader' }.to raise_error(ArgumentError,
                                                        /IP\.bind_layer\(.*FakeHeader/)

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
        expect(@pkt.is? 'Eth').to be(false)
      end

      it 'raises on unknown protocol' do
        expect { @pkt.is? 'IPOT' }.to raise_error(ArgumentError)
      end
    end

    describe '#calc_sum' do
      it 'recalculates packet checksums' do
        pending 'need UDP'
        pkt = Packet.gen('Eth').add('IP', src: '1.1.1.1', dst: '2.2.2.2').
              add('UDP', sport: 45768, dport: 80)
        pkt.body = 'abcdef'
        pkt.recalc
        expect(pkt.ip.sum).to eq(0)
        expect(pkt.udp.sum).to eq(0)
      end
    end
  end
end
