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
    end
  end
end
