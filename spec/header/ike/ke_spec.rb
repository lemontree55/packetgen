require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe KE do
        describe '#initialize' do
          it 'creates a KE payload with default values' do
            ke = KE.new
            expect(ke.next).to eq(0)
            expect(ke.flags).to eq(0)
            expect(ke.length).to eq(8)
            expect(ke.group_num).to eq(0)
            expect(ke.reserved).to eq(0)
            expect(ke.content).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              group_num: Transform::DH_ECP256,
              reserved: 0xffff,
              content: 'abcdefghij'
            }

            ke = KE.new(opts)
            opts.each do |k,v|
              expect(ke.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets KE from a binary string' do
            str = [12, 0x80, 13, 0x101, 0, 'abcde'].pack('CCnnnA*')
            ke = KE.new.read(str)
            expect(ke.next).to eq(12)
            expect(ke.flags).to eq(0x80)
            expect(ke.critical?).to be(true)
            expect(ke.length).to eq(13)
            expect(ke.group_num).to eq(0x101)
            expect(ke.reserved).to eq(0)
            expect(ke.content).to eq('abcde')
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            ke = KE.new(next: 1, group: 'ECP256', content: 'abcdefghijkl')
            ke.calc_length
            expected = "\x01\x00\x00\x14\x00\x13\x00\x00abcdefghijkl"
            expect(ke.to_s).to eq(force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            ke = KE.new
            str = ke.inspect
            expect(str).to be_a(String)
            (ke.fields - %i(body)).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end
      end
    end
  end
end
