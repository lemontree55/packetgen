require_relative '../spec_helper'

module PacketGen
  module Header

    describe DHCPv6 do
      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(DHCPv6)
          expect(UDP).to know_header(DHCPv6::Relay)
        end
      end

      describe '#read' do
        it 'read a DHCPv6 header' do
          raw = read_raw_packets('dhcpv6.pcapng').first
          pkt = PacketGen.parse(raw)
          expect(pkt.is? 'DHCPv6').to be(true)

          dhcpv6 = pkt.dhcpv6
          p dhcpv6
          expect(dhcpv6.msg_type).to eq(1)
          expect(dhcpv6.human_msg_type).to eq('SOLLICIT')
          expect(dhcpv6.transaction_id).to eq(0x100874)
          expect(dhcpv6.options.size).to eq(4)
          expect(dhcpv6.options.first.human_type).to eq('ClientID')
          expect(dhcpv6.options.first.length).to eq(14)
          expect(dhcpv6.options.first.duid.to_human).to eq('DUID_LLT<2015-01-02 21:52:08 UTC,08:00:27:fe:8f:95>')
        end
      end

      describe '#options' do
        let(:dhcpv6) { DHCPv6.new }

        it 'accepts a ServerID option as a hash' do
          dhcpv6.options << { type: 'ServerID', duid: DHCPv6::DUID_LL.new(link_addr: '08:00:27:fe:8f:95') }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::ServerID)
          expect(dhcpv6.options.first.type).to eq(2)
          expect(dhcpv6.options.first.human_type).to eq('ServerID')
          expect(dhcpv6.options.first.length).to eq(10)
          expect(dhcpv6.options.first.to_human).to eq('ServerID:DUID_LL<08:00:27:fe:8f:95>')
        end

        it 'accepts a IANA option as a hash' do
          dhcpv6.options << { type: 'IANA', iaid: 0x12345678, t1: 1, t2: 2 }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::IANA)
          expect(dhcpv6.options.first.type).to eq(3)
          expect(dhcpv6.options.first.human_type).to eq('IANA')
          expect(dhcpv6.options.first.length).to eq(12)
          expect(dhcpv6.options.first.to_human).to eq('IANA:0x12345678,1,2')
        end

        it 'accepts a IATA option as a hash' do
          dhcpv6.options << { type: 4, iaid: 0x12345678 }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::IATA)
          expect(dhcpv6.options.first.type).to eq(4)
          expect(dhcpv6.options.first.human_type).to eq('IATA')
          expect(dhcpv6.options.first.length).to eq(4)
          expect(dhcpv6.options.first.to_human).to eq('IATA:0x12345678')
        end

        it 'accepts a IAAddr option as a hash' do
          dhcpv6.options << {
            type: 'IAAddr',
            ipv6: '::1',
            preferred_lifetime: 150, 
            valid_lifetime: 50
          }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::IAAddr)
          expect(dhcpv6.options.first.type).to eq(5)
          expect(dhcpv6.options.first.length).to eq(24)
          expect(dhcpv6.options.first.to_human).to eq('IAAddr:::1,150,50')
        end

        it 'accepts a ORO option as a hash' do
          dhcpv6.options << { type: 'ORO' }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::ORO)
          expect(dhcpv6.options.first.type).to eq(6)
          expect(dhcpv6.options.first.length).to eq(0)
          expect(dhcpv6.options.first.to_human).to eq('ORO')
        end

        it 'accepts a Preference option as a hash' do
          dhcpv6.options << { type: 'Preference', value: 55 }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::Preference)
          expect(dhcpv6.options.first.type).to eq(7)
          expect(dhcpv6.options.first.length).to eq(1)
          expect(dhcpv6.options.first.to_human).to eq('Preference:55')
        end

        it 'accepts a ElapsedTime option as a hash' do
          dhcpv6.options << { type: 'ElapsedTime', value: 0x8000 }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::ElapsedTime)
          expect(dhcpv6.options.first.type).to eq(8)
          expect(dhcpv6.options.first.length).to eq(2)
          expect(dhcpv6.options.first.to_human).to eq('ElapsedTime:32768')
        end

        it 'accepts a RelayMessage option as a hash' do
          dhcpv6.options << { type: 'RelayMessage', data: 'message' }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::RelayMessage)
          expect(dhcpv6.options.first.type).to eq(9)
          expect(dhcpv6.options.first.length).to eq(7)
          expect(dhcpv6.options.first.to_human).to eq('RelayMessage:"message"')
        end

        it 'accepts a ServerUnicast option as a hash' do
          dhcpv6.options << { type: 'ServerUnicast', addr: '2:1::1' }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::ServerUnicast)
          expect(dhcpv6.options.first.type).to eq(12)
          expect(dhcpv6.options.first.length).to eq(16)
          expect(dhcpv6.options.first.to_human).to eq('ServerUnicast:2:1::1')
        end

        it 'accepts a StatusCode option as a hash' do
          dhcpv6.options << { type: 'StatusCode', value: 1 }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::StatusCode)
          expect(dhcpv6.options.first.type).to eq(13)
          expect(dhcpv6.options.first.length).to eq(2)
          expect(dhcpv6.options.first.to_human).to eq('StatusCode:1')
        end

        it 'accepts a RapidCommit option as a hash' do
          dhcpv6.options << { type: 'RapidCommit' }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::RapidCommit)
          expect(dhcpv6.options.first.type).to eq(14)
          expect(dhcpv6.options.first.length).to eq(0)
          expect(dhcpv6.options.first.to_human).to eq('RapidCommit')
        end
      end
    end
  end
end
