require_relative '../spec_helper'

module PacketGen
  module Types
    describe CString do
      describe '#initialize' do
        it 'build a CString with default value' do
          cs = CString.new
          expect(cs).to eq('')
          expect(cs.sz).to eq(1)
        end

        it 'accepts a static_length option' do
          cs = CString.new(static_length: 8)
          expect(cs.sz).to eq(8)
          expect(cs).to eq('')
        end
      end

      describe '#read' do
        it 'reads a CString' do
          cs = CString.new
          cs.read binary("abcd\x00")
          expect(cs.sz).to eq(5)
          expect(cs.length).to eq(4)
          expect(cs).to eq('abcd')
        end

        it 'reads a CString with static length' do
          cs = CString.new(static_length: 8)
          cs.read binary("abcd\x00\x00\x00\x00")
          expect(cs.sz).to eq(8)
          expect(cs.length).to eq(4)
          expect(cs).to eq('abcd')
        end
      end

      describe '#to_s' do
        it 'generates a null-terminated string' do
          cs = CString.new
          cs.read 'This is a String'
          expect(cs.to_s).to eq(binary("This is a String\x00"))
          expect(cs.length).to eq(16)
          expect(cs.sz).to eq(17)
        end

        it 'gets binary form for CString with previously forced length' do
          cs = CString.new(static_length: 20)
          cs.read 'This is a String'
          expect(cs.to_s).to eq(binary("This is a String\x00\x00\x00\x00"))
          expect(cs.length).to eq(16)
          expect(cs.sz).to eq(20)

          cs.read 'This is a too too long string'
          expect(cs.length).to eq(20)
          expect(cs).to eq('This is a too too lo')
          expect(cs.sz).to eq(20)
          expect(cs.to_s).to eq(binary("This is a too too l\x00"))
        end
      end

      context 'check Packet#add may set a CString (bug #91)' do
        it 'is fixed' do
          pkt = Packet.gen('BOOTP', file: 'test.txt')
          expect(pkt.bootp.file).to eq('test.txt')
          expect(pkt.bootp[:file].to_s).to eq('test.txt' + ([0] * 120).pack('C*'))
        end
      end
    end

    describe '#<<' do
      let(:cs) { CString.new }
      it 'accepts a string' do
        cs.read "abcd\x00"
        cs << 'efgh'
        expect(cs.to_human).to eq('abcdefgh')
      end

      it 'accepts another CString' do
        cs.read "abcd\x00"
        cs2 = CString.new
        cs2.read "efgh\x00"
        cs << cs2
        expect(cs.to_human).to eq('abcdefgh')
      end

      it 'returns itself' do
        cs.read "abcd\x00"
        cs2 = cs << 'efgh'
        expect(cs2.to_human).to eq('abcdefgh')
        expect(cs2.object_id).to eq(cs.object_id)
      end
    end
  end
end
