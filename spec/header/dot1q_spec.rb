require_relative '../spec_helper'

module PacketGen
  module Header
    describe Dot1q do
      describe 'binding' do
        it 'in Eth packets' do
          expect(Eth).to know_header(Dot1q).with(ethertype: 0x8100)
        end
        it 'accepts to be added in Eth packets' do
          pkt = PacketGen.gen('Eth')
          expect { pkt.add('Dot1q') }.to_not raise_error
          expect(pkt.eth.ethertype).to eq(0x8100)
        end
      end
    end
  end
end
