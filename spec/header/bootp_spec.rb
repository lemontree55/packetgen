require_relative '../spec_helper'

module PacketGen
  module Header

    describe BOOTP do
      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(BOOTP).with(sport: 67)
          expect(UDP).to know_header(BOOTP).with(dport: 67)
          expect(UDP).to know_header(BOOTP).with(sport: 68)
          expect(UDP).to know_header(BOOTP).with(dport: 68)
        end
      end

      describe '#read' do
        it 'read a BOOTP header' do
          raw = PcapNG::File.new.read_packet_bytes(File.join(__dir__, 'dhcp.pcapng')).first
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
          expect(bootp.chaddr).to eq(PacketGen.force_binary chaddr)
          expect(bootp.sname).to eq('')
          expect(bootp.file).to eq('')
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          raws = PcapNG::File.new.read_packet_bytes(File.join(__dir__, 'dhcp.pcapng'))
          packets = PcapNG::File.new.read_packets(File.join(__dir__, 'dhcp.pcapng'))
          packets.each_with_index do |pkt, i|
            expect(pkt.to_s).to eq(raws[i])
          end
        end
      end
    end
  end
end
