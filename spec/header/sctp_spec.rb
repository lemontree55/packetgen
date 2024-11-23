# frozen_string_literal: true

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
          expect { pkt.add('SCTP') }.not_to raise_error
          expect(pkt.ip.protocol).to eq(132)
        end

        it 'accepts to be added in IPv6 packets' do
          pkt = PacketGen.gen('IPv6')
          expect { pkt.add('SCTP') }.not_to raise_error
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
        let(:raw_packets) { read_raw_packets('sctp.pcapng') }

        it 'sets header from a string' do
          pkt = PacketGen.parse(raw_packets[0])
          expect(pkt.sctp.dport).to eq(80)
          expect(pkt.sctp.chunks.size).to eq(1)
          expect(pkt.sctp.chunks.first.type).to eq(1)
          expect(pkt.sctp.chunks.first.human_type).to eq('INIT')
        end

        it 'sets INIT chunk' do
          pkt = PacketGen.parse(raw_packets[0])
          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::InitChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['INIT'])
          expect(chunk.length).to eq(60)
          expect(chunk.initiate_tag).to eq(0x3bb99c46)
          expect(chunk.a_rwnd).to eq(106_496)
          expect(chunk.nos).to eq(10)
          expect(chunk.nis).to eq(65_535)
          expect(chunk.initial_tsn).to eq(724_401_842)

          expect(chunk.parameters[0]).to be_a(SCTP::IPv4Parameter)
          expect(chunk.parameters[0].value).to eq('155.230.24.155')
          expect(chunk.parameters[1]).to be_a(SCTP::IPv4Parameter)
          expect(chunk.parameters[1].value).to eq('155.230.24.156')
          expect(chunk.parameters[2]).to be_a(SCTP::SupportedAddrTypesParameter)
          expect(chunk.parameters[2].value.map(&:to_i)).to eq([5])
          expect(chunk.parameters[3]).to be_a(SCTP::ECNParameter)
          expect(chunk.parameters[4]).to be_a(SCTP::Parameter)
          expect(chunk.parameters[4].type).to eq(0xc000)
          expect(chunk.parameters[5]).to be_a(SCTP::Parameter)
          expect(chunk.parameters[5].type).to eq(0xc006)
          expect(chunk.parameters[5].value).to eq([0].pack('N'))
        end

        it 'sets INIT ACK chunk' do
          pkt = PacketGen.parse(raw_packets[1])
          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::InitAckChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['INIT_ACK'])
          expect(chunk.initiate_tag).to eq(0xd26ac1e5)
          expect(chunk.a_rwnd).to eq(106_496)
          expect(chunk.nos).to eq(10)
          expect(chunk.nis).to eq(10)
          expect(chunk.initial_tsn).to eq(1_677_732_374)

          expect(chunk.parameters[0]).to be_a(SCTP::StateCookieParameter)
          expect(chunk.parameters[0].length).to eq(196)
          expect(chunk.parameters[0].value[0, 2]).to eq(binary("\xb3\x49"))
          expect(chunk.parameters[0].value[-2, 2]).to eq(binary("\x00\x00"))
        end

        it 'sets COOKIE_ECHO chunk' do
          pkt = PacketGen.parse(raw_packets[2])
          expect(pkt.sctp.verification_tag).to eq(0xd26ac1e5)

          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::CookieEchoChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['COOKIE_ECHO'])
          expect(chunk.length).to eq(196)
          expect(chunk.cookie.size).to eq(192)
          expect(chunk.cookie[0, 4]).to eq(binary("\xb3\x49\x30\x15"))
        end

        it 'sets COOKIE_ACK chunk' do
          pkt = PacketGen.parse(raw_packets[3])
          expect(pkt.sctp.verification_tag).to eq(0x3bb99c46)

          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::CookieAckChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['COOKIE_ACK'])
          expect(chunk.length).to eq(4)
        end

        it 'sets DATA chunk' do
          pkt = PacketGen.parse(raw_packets[4])
          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::DataChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['DATA'])
          expect(chunk.flags).to eq(3)
          expect(chunk.length).to eq(419)
          expect(chunk.tsn).to eq(0x2b2d7eb2)
          expect(chunk.stream_id).to eq(0)
          expect(chunk.stream_sn).to eq(0)
          expect(chunk.ppid).to eq(0)
          expect(chunk.body).to start_with('GET /')
        end

        it 'sets SACK chunk' do
          pkt = PacketGen.parse(raw_packets[5])
          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::SackChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['SACK'])
          expect(chunk.flags).to eq(0)
          expect(chunk.length).to eq(16)
          expect(chunk.ctsn_ack).to eq(0x2b2d7eb2)
          expect(chunk.a_rwnd).to eq(0x19e6d)
          expect(chunk.num_gap).to eq(0)
          expect(chunk.num_dup_tsn).to eq(0)
        end

        it 'sets SHUTDOWN chunk' do
          pkt = PacketGen.parse(raw_packets[-3])
          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::ShutdownChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['SHUTDOWN'])
          expect(chunk.flags).to eq(0)
          expect(chunk.length).to eq(8)
          expect(chunk.ctsn_ack).to eq(0x64002a26)
        end

        it 'sets SHUTDOWN_ACK chunk' do
          pkt = PacketGen.parse(raw_packets[-2])
          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::ShutdownAckChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['SHUTDOWN_ACK'])
          expect(chunk.flags).to eq(0)
          expect(chunk.length).to eq(4)
        end

        it 'sets SHUTDOWN_COMPLETE chunk' do
          pkt = PacketGen.parse(raw_packets[-1])
          chunk = pkt.sctp.chunks.first
          expect(chunk).to be_a(SCTP::ShutdownCompleteChunk)
          expect(chunk.type).to eq(SCTP::BaseChunk::TYPES['SHUTDOWN_COMPLETE'])
          expect(chunk.flags).to eq(0)
          expect(chunk.length).to eq(4)
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
          chunk0.body << '1234'
          chunk1.body << '12345678'
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
