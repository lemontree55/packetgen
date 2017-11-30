require_relative '../spec_helper'

module PacketGen
  module Header

    describe TFTP do
      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(TFTP).with(dport: 69)
        end
      end
      
      describe '#read' do
        let(:tftp) { TFTP.new }

        it 'reads a known TFTP header' do
          ary = [2, 'path/to/file', 'netascii']
          raw = ary.pack('nZ*Z*')
          mytftp = tftp.read(raw)
          expect(mytftp.opcode).to eq(ary[0])
          expect(mytftp.human_opcode).to eq('WRQ')
          expect(mytftp.filename).to eq(ary[1])
          expect(mytftp.mode).to eq(ary[2])
        end

        it 'reads an unknown TFTP header' do
          raw = (8..15).to_a.pack('nC*')
          mytftp = tftp.read(raw)
          expect(mytftp.opcode).to eq(8)
          expect(mytftp.human_opcode).to eq('<unknown:8>')
          expect(mytftp.body).to eq(PacketGen.force_binary "\x09\x0a\x0b\x0c\x0d\x0e\x0f")
        end
      end
    end
  end
end
