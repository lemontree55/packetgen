# frozen_string_literal: true

require_relative '../spec_helper'

DUID_LLT_DATA = "\x00\x01\x00\x01\x29\xc0\xde\x21\x00\x11\x22\x33\x44\x55".b.freeze
DUID_EN_DATA = "\x00\x02\x00\x00\x00\t\f\xC0\x84\xDD\x03\x00\t\x12".b.freeze
DUID_LL_DATA = "\x00\x03\x00\x01\x00\x11\x22\x33\x44\x55".b.freeze
DUID_OTHER_DATA = "\x00\xF0\x00\x00\x00\x00".b.freeze

module PacketGen
  module Header
    describe DHCPv6 do
      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(DHCPv6)
          expect(UDP).to know_header(DHCPv6::Relay)
        end

        it 'accepts to be added in UDP packets' do
          pkt = PacketGen.gen('UDP')
          expect { pkt.add('DHCPv6') }.not_to raise_error
          expect(pkt.udp.sport).to eq(546)
          expect(pkt.udp.dport).to eq(547)

          pkt = PacketGen.gen('UDP')
          expect { pkt.add('DHCPv6::Relay') }.not_to raise_error
          expect(pkt.udp.sport).to eq(546)
        end
      end

      describe '#read' do
        it 'reads a DHCPv6 header' do
          raw = read_raw_packets('dhcpv6.pcapng').first
          pkt = PacketGen.parse(raw)
          expect(pkt.is?('DHCPv6')).to be(true)

          dhcpv6 = pkt.dhcpv6
          expect(dhcpv6.msg_type).to eq(1)
          expect(dhcpv6.human_msg_type).to eq('SOLLICIT')
          expect(dhcpv6.transaction_id).to eq(0x100874)
          expect(dhcpv6.options.size).to eq(4)
          expect(dhcpv6.options.first.human_type).to eq('ClientID')
          expect(dhcpv6.options.first.length).to eq(14)
          expect(dhcpv6.options.first.duid.to_human).to eq('DUID_LLT<2015-01-02 21:52:08 UTC,08:00:27:fe:8f:95>')
        end

        it 'reads a DHCPv6::Relay header' # TODO: need a file to parse
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
          dhcpv6.options << { type: 'StatusCode', status_code: 1 }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::StatusCode)
          expect(dhcpv6.options.first.type).to eq(13)
          expect(dhcpv6.options.first.length).to eq(2)
          expect(dhcpv6.options.first.to_human).to eq('StatusCode:1')
        end

        it 'accepts a StatusCode option as a hash, with a message' do
          dhcpv6.options << { type: 'StatusCode', status_code: 2, status_message: 'code 2' }
          expect(dhcpv6.options.size).to eq(1)
          expect(dhcpv6.options.first).to be_a(DHCPv6::StatusCode)
          expect(dhcpv6.options.first.type).to eq(13)
          expect(dhcpv6.options.first.length).to eq(8)
          expect(dhcpv6.options.first.to_human).to eq('StatusCode:2')
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

    describe DHCPv6::DUID do
      let(:duid) { DHCPv6::DUID.new }

      describe '#read' do
        it 'infers a DUID::LLT object when reading a DUID-LLT header' do
          d = duid.read(DUID_LLT_DATA)
          expect(d).to be_a(DHCPv6::DUID_LLT)
          expect(d.type).to eq(DHCPv6::DUID::TYPES['DUID-LLT'])
          expect(d.human_type).to eq('DUID-LLT')
          expect(d.htype).to eq(1)
          expect(d.time).to eq(Time.utc(2022, 3, 13, 16, 53, 53))
          expect(d.link_addr).to eq('00:11:22:33:44:55')
        end

        it 'infers a DUID::EN object when reading a DUID-EN header' do
          d = duid.read(DUID_EN_DATA)
          expect(d).to be_a(DHCPv6::DUID_EN)
          expect(d.type).to eq(DHCPv6::DUID::TYPES['DUID-EN'])
          expect(d.human_type).to eq('DUID-EN')
          expect(d.en).to eq(9)
          expect(d.identifier).to eq("\f\xC0\x84\xDD\x03\x00\t\x12".b)
        end

        it 'infers a DUID::LL object when reading a DUID-LL header' do
          d = duid.read(DUID_LL_DATA)
          expect(d).to be_a(DHCPv6::DUID_LL)
          expect(d.type).to eq(DHCPv6::DUID::TYPES['DUID-LL'])
          expect(d.human_type).to eq('DUID-LL')
          expect(d.htype).to eq(1)
          expect(d.link_addr).to eq('00:11:22:33:44:55')
        end

        it 'returns a DUID object if DUID type is not recognized' do
          d = duid.read(DUID_OTHER_DATA)
          expect(d).to be_a(DHCPv6::DUID)
          expect(d.type).to eq(0xf0)
          expect(d.body).to eq("\x00\x00\x00\x00".b)
        end
      end

      describe '#to_human' do
        it 'returns a huùman-readable string' do
          d = duid.read(DUID_OTHER_DATA)
          expect(d.to_human).to match(/^DUID<240,.*>$/)
          d = duid.read(DUID_LLT_DATA)
          expect(d.to_human).to eq('DUID_LLT<2022-03-13 16:53:53 UTC,00:11:22:33:44:55>')
          d = duid.read(DUID_EN_DATA)
          expect(d.to_human).to match(/^DUID_EN<0x9,.*>$/)
          d = duid.read(DUID_LL_DATA)
          expect(d.to_human).to eq('DUID_LL<00:11:22:33:44:55>')
        end
      end
    end

    describe DHCPv6::DUID_LLT do
      describe '#time=' do
        it 'sets time' do
          new_time = Time.utc(2011, 1, 1, 12, 13, 14)
          duid = DHCPv6::DUID_LLT.new
          old_time = duid.time
          duid.time = new_time
          expect(duid.time).not_to eq(old_time)
          expect(duid.time).to eq(new_time)
          expect(duid[:time].to_i).to eq(347_199_194)
        end
      end
    end
  end
end
