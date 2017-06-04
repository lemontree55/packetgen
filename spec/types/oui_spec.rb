require_relative '../spec_helper'

module PacketGen
  module Types
    describe OUI do

      describe '#initialize' do
        it 'returns a OUI with default values' do
          oui = OUI.new
          expect(oui.b2).to eq(0)
          expect(oui.b1).to eq(0)
          expect(oui.b0).to eq(0)
        end

        it 'accepts field options' do
          oui = OUI.new(b2: 45, b1: 2, b0: 128)
          expect(oui.b2).to eq(45)
          expect(oui.b1).to eq(2)
          expect(oui.b0).to eq(128)
        end
      end

      describe '#read' do
        it 'reads a OUI from a binary string' do
          bin_str = [1, 2, 3].pack('C3')
          oui = OUI.new.read(bin_str)
          expect(oui.b2).to eq(1)
          expect(oui.b1).to eq(2)
          expect(oui.b0).to eq(3)
        end
      end

      describe '#to_human' do
        it 'returns a human readable string' do
          oui = OUI.new(b2: 0x81, b1: 0x5f, b0: 0xde)
          expect(oui.to_human).to eq('81:5f:de')
        end
      end
      describe '#from_human' do
        it 'sets OUI from a human readable string' do
          oui = OUI.new
          oui.from_human '81:5f:de'
          expect(oui.b2).to eq(0x81)
          expect(oui.b1).to eq(0x5f)
          expect(oui.b0).to eq(0xde)
        end

        it 'raises on malformed string' do
          oui = OUI.new
          expect { oui.from_human '01:02' }.to raise_error(ArgumentError, 'not a OUI')
        end
      end
    end
  end
end
