require_relative '../spec_helper'

module PacketGen
  module Types
    describe IntString do
      describe '#initialize' do
        it 'accepts a len_type option' do
          is = IntString.new
          expect(is.sz).to eq(1)

          is = IntString.new('', Int16)
          expect(is.sz).to eq(2)
          is = IntString.new('', Int32)
          expect(is.sz).to eq(4)
          is = IntString.new('', Int64)
          expect(is.sz).to eq(8)
        end
      end

      describe '#read' do
        let(:is8) { IntString.new }
        let(:is32) { IntString.new('', Int32) }

        it 'reads an IntString' do
          is8.read PacketGen.force_binary("\x04abcd")
          expect(is8.length).to eq(4)
          expect(is8.string).to eq('abcd')

          is32.read PacketGen.force_binary("\x00\x00\x00\x06abcdef")
          expect(is32.length).to eq(6)
          expect(is32.string).to eq('abcdef')
        end

        it 'raises on too short string for given type' do
          str = "\x01a"
          expect { is32.read str }.to raise_error(ParseError, /too short/)
        end
      end

      describe '#to_s' do
        let(:is8) { IntString.new }
        let(:is16) { IntString.new('', Int16) }

        it 'gets binary form for IntString' do
          is8.string = 'This is a String'
          expect(is8.to_s).to eq(PacketGen.force_binary("\x10This is a String"))
          is16.string = 'This is another String'
          expect(is16.to_s).to eq(PacketGen.force_binary("\x00\x16This is another String"))
        end

        it 'gets binary form for IntString with previously forced length' do
          is8.string = 'This is a String'
          is8.length = 17
          expect(is8.to_s).to eq(PacketGen.force_binary("\x11This is a String"))
          is8.length = 10
          expect(is8.to_s).to eq(PacketGen.force_binary("\x0aThis is a String"))
        end
      end
    end
  end
end
