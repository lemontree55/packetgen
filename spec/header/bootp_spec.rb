require_relative '../spec_helper'

module PacketGen
  module Header
    describe BOOTP do
      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(BOOTP).with(sport: 67, dport: 68)
          expect(UDP).to know_header(BOOTP).with(sport: 68, dport: 67)
        end
        it 'accepts to be added in UDP packets' do
          pkt = PacketGen.gen('UDP')
          expect { pkt.add('BOOTP') }.to_not raise_error
          expect(pkt.udp.sport).to eq(67)
          expect(pkt.udp.dport).to eq(68)
        end
      end

      describe '#read' do
        it 'read a BOOTP header' do
          raw = read_raw_packets('dhcp.pcapng').first
          pkt = PacketGen.parse(raw)
          expect(pkt.is? 'BOOTP').to be(true)
          bootp = pkt.bootp
          expect(bootp.op).to eq(1)
          expect(bootp.htype).to eq(1)
          expect(bootp.hlen).to eq(6)
          expect(bootp.hops).to eq(0)
          expect(bootp.xid).to eq(15645)
          expect(bootp.secs).to eq(0)
          expect(bootp.flags).to eq(0)
          expect(bootp.ciaddr).to eq('0.0.0.0')
          expect(bootp.yiaddr).to eq('0.0.0.0')
          expect(bootp.siaddr).to eq('0.0.0.0')
          expect(bootp.giaddr).to eq('0.0.0.0')
          chaddr = "\x00\v\x82\x01\xFCB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          expect(bootp.chaddr).to eq(binary chaddr)
          expect(bootp.sname).to eq('')
          expect(bootp.file).to eq('')
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          raws = read_raw_packets('dhcp.pcapng')
          packets = read_packets('dhcp.pcapng')
          packets.each_with_index do |pkt, i|
            expect(pkt.to_s).to eq(binary raws[i])
          end
        end
      end

      describe '#reply!' do
        it 'inverts opcode, if known' do
          bootp = BOOTP.new
          bootp.reply!
          expect(bootp.op).to eq(2)
          bootp.reply!
          expect(bootp.op).to eq(1)
        end

        it 'does nothing, if opcode is unknown' do
          bootp = BOOTP.new(op: 45)
          bootp.reply!
          expect(bootp.op).to eq(45)
        end
      end
    end
  end
end
