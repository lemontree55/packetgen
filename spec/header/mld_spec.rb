# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module Header
    describe MLD do
      describe 'bindings' do
        it 'in ICMPv6 packets' do
          expect(ICMPv6).to know_header(MLD).with(type: 130)
          expect(ICMPv6).to know_header(MLD).with(type: 131)
          expect(ICMPv6).to know_header(MLD).with(type: 132)
        end

        it 'accepts to be added in ICMPv6 packets' do
          pkt = PacketGen.gen('ICMPv6')
          expect { pkt.add('MLD') }.not_to raise_error
          expect(pkt.icmpv6.type).to eq(130)
        end
      end

      describe '#initialize' do
        it 'creates a MLD header with default values' do
          mld = MLD.new
          expect(mld).to be_a(MLD)
          expect(mld.max_resp_delay).to eq(0)
          expect(mld.reserved).to eq(0)
          expect(mld.mcast_addr).to eq('::')
        end

        it 'accepts options' do
          mld = MLD.new(max_resp_delay: 254, reserved: 0x1234,
                        mcast_addr: 'ff02::1')
          expect(mld.max_resp_delay).to eq(254)
          expect(mld.reserved).to eq(0x1234)
          expect(mld.mcast_addr).to eq('ff02::1')
        end
      end

      describe '#read' do
        let(:mld) { MLD.new }

        it 'sets header from a string' do
          str = (1..mld.sz).to_a.pack('C*') + 'body'
          mld.read str
          expect(mld.max_resp_delay).to eq(0x102)
          expect(mld.reserved).to eq(0x304)
          expect(mld.mcast_addr).to eq('506:708:90a:b0c:d0e:f10:1112:1314')
        end

        it 'reads a MLD header in a real packet' do
          pkt = PacketGen.gen('IPv6', src: 'fe80::1', dst: 'ff02::1', hop: 1)
                         .add('IPv6::HopByHop')
                         .add('ICMPv6', type: 130, code: 0)
          pkt.ipv6_hopbyhop.options << { type: 'router_alert', value: BinStruct::Int16.new(value: 0).to_s }
          pkt.body = +"\x00\x7f\x00\x00" <<
                     ([0] * 16).pack('C*')
          pkt.calc
          parsed_pkt = PacketGen.parse(pkt.to_s)
          expect(parsed_pkt.is?('IPv6')).to be(true)
          expect(parsed_pkt.is?('ICMPv6')).to be(true)
          expect(parsed_pkt.is?('MLD')).to be(true)
          expect(parsed_pkt.mld.max_resp_delay).to eq(127)
          expect(parsed_pkt.mld.reserved).to eq(0)
          expect(parsed_pkt.mld.mcast_addr).to eq('::')
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          mld = MLD.new(max_resp_delay: 20,
                        mcast_addr: 'ff02::1')
          expected = +"\x00\x14\x00\x00"
          expected << [0xff02, 0, 0, 0, 0, 0, 0, 1].pack('n*')
          expect(mld.to_s).to eq(expected)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          mld = MLD.new
          str = mld.inspect
          expect(str).to be_a(String)
          (mld.attributes - %i[body]).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe '#mldize' do
        it 'fixup IP header' do
          pkt = PacketGen.gen('IPv6', src: '::1', dst: '::2')
          pkt.add('ICMPv6')
          pkt.add('MLD')
          pkt.mldize
          expect(pkt.ipv6.hop).to eq(1)
          expect(pkt.ipv6.next).to eq(0)
          expect(pkt.ipv6.length).to eq(32)
          expect(pkt.is?('IPv6::HopByHop')).to be(true)
          expect(pkt.ipv6_hopbyhop.options.size).to eq(2)
          expect(pkt.ipv6_hopbyhop.options[0].human_type).to eq('router_alert')
          expect(pkt.ipv6_hopbyhop.options[0].value).to eq("\x00\x00")
          expect(pkt.ipv6_hopbyhop.options[1].to_human).to eq('pad2')
          expect(pkt.ipv6_hopbyhop.next).to eq(ICMPv6::IP_PROTOCOL)
          expect(pkt.icmpv6.checksum).to eq(0x7daa)
          expected = +"\x60\x00\x00\x00\x00\x20\x00\x01".b
          expected << "\x00".b * 15 << "\x01".b
          expected << "\x00".b * 15 << "\x02".b
          expected << "\x3a\x00\x05\x02\x00\x00\x01\x00".b
          expected << "\x82\x00\x7d\xaa".b
          expected << "\x00\x00\x00\x00".b
          expected << "\x00".b * 16
          expect(pkt.to_s).to eq(expected)
        end
      end
    end
  end
end
