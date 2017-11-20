require_relative '../spec_helper'

module PacketGen
  module Header

    describe DHCP do
      #let(:dhcp_pcapng) { File.join(__dir__, 'dhcp.pcapng') }

      describe 'binding' do
        it 'in BOOTP packets' do
          expect(BOOTP).to know_header(DHCP)
        end
      end

      describe '#read' do
        it 'read a DHCP header' do
          raw = PcapNG::File.new.read_packet_bytes(File.join(__dir__, 'dhcp.pcapng')).first
          pkt = PacketGen.parse(raw)
          expect(pkt.is? 'BOOTP').to be(true)
          expect(pkt.is? 'DHCP').to be(true)

          dhcp = pkt.dhcp
          expect(dhcp.magic).to eq(0x63825363)
          expect(dhcp.options.size).to eq(8)
          expect(dhcp.options.first.human_type).to eq('message-type')
          expect(dhcp.options.first.length).to eq(1)
          expect(dhcp.options.first.value).to eq(1)
          expect(dhcp.options.last.human_type).to eq('pad')
          expect(dhcp.options.last.length).to eq(0)
          expect(dhcp.options.last.value).to eq('')
        end
      end
    end
  end
end
