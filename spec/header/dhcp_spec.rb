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
          raw = read_raw_packets('dhcp.pcapng').first
          pkt = PacketGen.parse(raw)
          expect(pkt.is? 'BOOTP').to be(true)
          expect(pkt.is? 'DHCP').to be(true)

          dhcp = pkt.dhcp
          expect(dhcp.magic).to eq(0x63825363)
          expect(dhcp.options.size).to eq(12)
          expect(dhcp.options.first.human_type).to eq('message-type')
          expect(dhcp.options.first.length).to eq(1)
          expect(dhcp.options.first.value).to eq(1)
          expect(dhcp.options.last.human_type).to eq('pad')
        end
      end

      describe '#options' do
        let(:dhcp) { DHCP.new }

        it 'accepts an option as a hash' do
          dhcp.options << { type: 'router', value: '10.0.0.1'}
          expect(dhcp.options.size).to eq(1)
          expect(dhcp.options.first.type).to eq(3)
          expect(dhcp.options.first.human_type).to eq('router')
          expect(dhcp.options.first.length).to eq(4)
          expect(dhcp.options.first.value).to eq('10.0.0.1')
        end

        it 'accepts a pad option' do
          dhcp.options << { type: 'pad' }
          expect(dhcp.options.size).to eq(1)
          expect(dhcp.options.first).to be_a(DHCP::Pad)
          dhcp.options << { type: 0 }
          expect(dhcp.options.size).to eq(2)
          expect(dhcp.options.last).to be_a(DHCP::Pad)
        end

        it 'accepts a end option' do
          dhcp.options << { type: 'end' }
          expect(dhcp.options.size).to eq(1)
          expect(dhcp.options.first).to be_a(DHCP::End)
          dhcp.options << { type: 255 }
          expect(dhcp.options.size).to eq(2)
          expect(dhcp.options.last).to be_a(DHCP::End)
        end
      end
    end
  end
end
