require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe Nonce do
        describe '#initialize' do
          it 'creates a Nonce payload with default values' do
            nonce = Nonce.new
            expect(nonce.next).to eq(0)
            expect(nonce.flags).to eq(0)
            expect(nonce.length).to eq(4)
            expect(nonce.content).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              content: 'abcdefghij'
            }

            nonce = Nonce.new(opts)
            opts.each do |k,v|
              expect(nonce.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets Nonce from a binary string' do
            str = [12, 0x85, 9, 'abcde'].pack('CCnA*')
            nonce = Nonce.new.read(str)
            expect(nonce.next).to eq(12)
            expect(nonce.flags).to eq(0x85)
            expect(nonce.critical?).to be(true)
            expect(nonce.hreserved).to eq(5)
            expect(nonce.length).to eq(9)
            expect(nonce.content).to eq('abcde')
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            nonce = Nonce.new(next: 2, content: 'abcdefghijkl')
            nonce.calc_length
            expected = "\x02\x00\x00\x10abcdefghijkl"
            expect(nonce.to_s).to eq(force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            nonce = Nonce.new
            str = nonce.inspect
            expect(str).to be_a(String)
            (nonce.fields - %i(body)).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end
      end
    end
  end
end
