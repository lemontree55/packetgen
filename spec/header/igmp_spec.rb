# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module Header
    describe IGMP do
      describe 'bindings' do
        it 'in IP packets' do
          expect(IP).to know_header(IGMP).with(protocol: 2, frag: 0, ttl: 1, tos: 0)
        end

        it 'accepts to be added in IP packets' do
          pkt = PacketGen.gen('IP')
          expect { pkt.add('IGMP') }.not_to raise_error
          expect(pkt.ip.protocol).to eq(2)
          expect(pkt.ip.frag).to eq(0)
          expect(pkt.ip.ttl).to eq(1)
          expect(pkt.ip.tos).to eq(0)
        end
      end

      describe '#initialize' do
        it 'creates a IGMP header with default values' do
          igmp = IGMP.new
          expect(igmp).to be_a(IGMP)
          expect(igmp.max_resp_time).to eq(0)
          expect(igmp.checksum).to eq(0)
          expect(igmp.group_addr).to eq('0.0.0.0')
        end

        it 'accepts options' do
          igmp = IGMP.new(type: 255, max_resp_time: 254, checksum: 0x1234,
                          group_addr: '224.0.0.1')
          expect(igmp.type).to eq(255)
          expect(igmp.max_resp_time).to eq(254)
          expect(igmp.checksum).to eq(0x1234)
          expect(igmp.group_addr).to eq('224.0.0.1')
        end
      end

      describe '#read' do
        let(:igmp) { IGMP.new }

        it 'sets header from a string' do
          str = (1..igmp.sz).to_a.pack('C*') + 'body'
          igmp.read str
          expect(igmp.type).to eq(1)
          expect(igmp.max_resp_time).to eq(2)
          expect(igmp.checksum).to eq(0x0304)
          expect(igmp.group_addr).to eq('5.6.7.8')
        end

        it 'reads a IGMP header in a real packet' do
          pkt = PacketGen.gen('IP', src: '192.168.0.1', dst: '224.0.0.1',
                                    ttl: 1, protocol: 2)
          pkt.body = "\x11\x00\xee\xff\x00\x00\x00\x00"
          parsed_pkt = PacketGen.parse(pkt.to_s)
          expect(parsed_pkt.is?('IP')).to be(true)
          expect(parsed_pkt.is?('IGMP')).to be(true)
          expect(parsed_pkt.igmp.human_type).to eq('MembershipQuery')
          expect(parsed_pkt.igmp.max_resp_time).to eq(0)
          expect(parsed_pkt.igmp.group_addr).to eq('0.0.0.0')
        end
      end

      describe '#calc_checksum' do
        it 'computes IGMP header checksum' do
          igmp = IGMP.new(type: 0x11, max_resp_time: 20)
          igmp.calc_checksum
          expect(igmp.calc_checksum).to eq(0xeeeb)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          igmp = IGMP.new(type: 'MembershipQuery', max_resp_time: 20,
                          group_addr: '224.0.0.1')
          igmp.calc_checksum
          expected = binary("\x11\x14\x0e\xea\xe0\x00\x00\x01")
          expect(igmp.to_s).to eq(expected)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          igmp = IGMP.new
          str = igmp.inspect
          expect(str).to be_a(String)
          (igmp.attributes - %i[body]).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe '#igmpize' do
        it 'fixup IP header' do
          pkt = PacketGen.gen('IP', src: '75.12.34.56', dst: '224.0.0.1', id: 0)
          pkt.add('IGMP', type: 0x11)
          pkt.igmpize
          expect(pkt.ip.ttl).to eq(1)
          expect(pkt.ip.options.size).to eq(1)
          expect(pkt.ip.options[0]).to be_a(IP::RA)
          expected = +"\x46\x00\x00\x20\x00\x00\x00\x00\x01\x02\xd7\x92"
          expected << "\x4b\x0c\x22\x38\xe0\x00\x00\x01\x94\x04\x00\x00"
          expected << "\x11\x00\xee\xff\x00\x00\x00\x00"
          expect(pkt.to_s).to eq(binary(expected))
        end
      end
    end
  end
end
