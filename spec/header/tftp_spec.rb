# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module Header
    describe TFTP do
      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(TFTP).with(dport: 69)
        end

        it 'accepts to be added in UDP packets' do
          pkt = PacketGen.gen('UDP')
          expect { pkt.add('TFTP') }.not_to raise_error
          expect(pkt.udp.dport).to eq(69)
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
          expect(mytftp.body).to eq("\x09\x0a\x0b\x0c\x0d\x0e\x0f".b)
        end
      end
    end

    describe '#decode!' do
      let(:packets) { read_packets('tftp.pcapng') }

      it 'decodes subsequent TFTP packets from first request' do
        tftp = packets.shift
        expect(tftp.is?('TFTP')).to be(true)
        expect(tftp.is?('TFTP::RRQ')).to be(true)
        packets.each do |pkt|
          expect(pkt.is?('TFTP')).to be(false)
        end

        tftp.tftp.decode!(packets)
        packets.each do |pkt|
          expect(pkt.is?('TFTP')).to be(true)
        end

        expect(packets[0].is?('TFTP::DATA')).to be(true)
        expect(packets[0].udp.sport).to eq(3445)
        expect(packets[0].udp.dport).to eq(50_618)
        expect(packets[0].tftp.opcode).to eq(3)
        expect(packets[0].tftp.block_num).to eq(1)
        expect(packets[0].udp.length - 8 - 4).to eq(512)
        expect(packets[1].is?('TFTP::ACK')).to be(true)
        expect(packets[1].udp.dport).to eq(3445)
        expect(packets[1].udp.sport).to eq(50_618)
        expect(packets[1].tftp.opcode).to eq(4)
        expect(packets[1].tftp.block_num).to eq(1)
        expect(packets[2].is?('TFTP::DATA')).to be(true)
        expect(packets[2].udp.sport).to eq(3445)
        expect(packets[2].udp.dport).to eq(50_618)
        expect(packets[2].tftp.opcode).to eq(3)
        expect(packets[2].tftp.block_num).to eq(2)
        expect(packets[2].udp.length - 8 - 4).to be < 512
        expect(packets[3].is?('TFTP::ACK')).to be(true)
        expect(packets[3].udp.dport).to eq(3445)
        expect(packets[3].udp.sport).to eq(50_618)
        expect(packets[3].tftp.opcode).to eq(4)
        expect(packets[3].tftp.block_num).to eq(2)
      end
    end
  end
end
