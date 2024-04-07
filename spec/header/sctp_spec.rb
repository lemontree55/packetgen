require_relative '../spec_helper'

module PacketGen
  module Header
    describe SCTP do
      describe 'binding' do
        it 'in IP packets' do
          expect(IP).to know_header(SCTP).with(protocol: 132)
          expect(IPv6).to know_header(SCTP).with(next: 132)
        end
        it 'accepts to be added in IP packets' do
          pkt = PacketGen.gen('IP')
          expect { pkt.add('SCTP') }.to_not raise_error
          expect(pkt.ip.protocol).to eq(132)
        end
        it 'accepts to be added in IPv6 packets' do
          pkt = PacketGen.gen('IPv6')
          expect { pkt.add('SCTP') }.to_not raise_error
          expect(pkt.ipv6.next).to eq(132)
        end
      end

      describe '#initialize' do
        it 'creates a SCTP header with default value' do
          sctp = SCTP.new
          expect(sctp).to be_a(SCTP)
          expect(sctp.sport).to eq(0)
          expect(sctp.dport).to eq(0)
          expect(sctp.verification_tag).to eq(0)
          expect(sctp.checksum).to eq(0)
        end
      end

      describe '#read' do
        it 'sets header from a string' do
          data = read_raw_packets('sctp.pcapng')[0]
          pkt = PacketGen.parse(data)
          expect(pkt.sctp.dport).to eq(80)
          expect(pkt.sctp.chunks.size).to eq(1)
          expect(pkt.sctp.chunks.first.type).to eq(1)
          expect(pkt.sctp.chunks.first.human_type).to eq('INIT')
        end
      end

      describe '#calc_chekcsum' do
        it 'updates SCTP packet checksum' do
          pkt = read_packets('sctp.pcapng')[0]
          orig_crc = pkt.sctp.checksum
          pkt.calc_checksum
          expect(pkt.sctp.checksum).to eq(orig_crc)
        end
      end

      describe '#calc_length' do
        it 'updates length field of all chunks' do
          sctp = SCTP.new
          sctp.chunks << SCTP::UnknownChunk.new(type: 55)
          sctp.chunks << SCTP::UnknownChunk.new(type: 56)

          chunk0 = sctp.chunks[0]
          chunk1 = sctp.chunks[1]
          chunk0.body << "1234"
          chunk1.body << "12345678"
          sctp.calc_length
          expect(chunk0.length).to eq(8)
          expect(chunk1.length).to eq(12)
        end
      end

      describe '#chunks' do
        it 'accepts Chunks through <<' do
          sctp = SCTP.new
          sctp.chunks << SCTP::InitChunk.new
          sctp.chunks << SCTP::DataChunk.new
          expect(sctp.chunks.size).to eq(2)
        end

        it 'accepts Hash through <<' do
          sctp = SCTP.new
          sctp.chunks << { type: 'INIT' }
          sctp.chunks << { type: 'DATA' }
          expect(sctp.chunks.size).to eq(2)
          expect(sctp.chunks[0]).to be_a(SCTP::InitChunk)
          expect(sctp.chunks[1]).to be_a(SCTP::DataChunk)
        end
      end

      it '#inspect shows chunks as headers' do
        sctp = SCTP.new
        sctp.chunks << { type: 'INIT' }
        sctp.chunks << { type: 'DATA' }
        inspect_str = sctp.inspect

        expect(inspect_str).to include('-- PacketGen::Header::SCTP::InitChunk')
        expect(inspect_str).to include('-- PacketGen::Header::SCTP::DataChunk')
      end
    end
  end
end
