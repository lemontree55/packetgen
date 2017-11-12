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
          p pkt
          expect(pkt.is? 'BOOTP').to be(true)
        end
      end
    end
  end
end
