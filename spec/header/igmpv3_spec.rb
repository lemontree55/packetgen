require_relative '../spec_helper'

module PacketGen
  module Header

    describe IGMPv3 do
      describe 'bindings' do
        it 'in IP packets' do
          expect(IP).to know_header(IGMPv3).with(protocol: 2, frag: 0, ttl: 1, tos: 0xc0)
        end
        it 'accepts to be added in IP packets' do
          pkt = PacketGen.gen('IP')
          expect { pkt.add('IGMPv3') }.to_not raise_error
          expect(pkt.ip.protocol).to eq(2)
          expect(pkt.ip.frag).to eq(0)
          expect(pkt.ip.ttl).to eq(1)
          expect(pkt.ip.tos).to eq(0xc0)
        end
      end

      describe '#initialize' do
        it 'creates a IGMPv3 header with default values' do
          igmp = IGMPv3.new
          expect(igmp).to be_a(IGMP)
          expect(igmp.max_resp_time).to eq(0)
          expect(igmp.checksum).to eq(0)
        end

        it 'accepts options' do
          igmp = IGMPv3.new(type: 255, max_resp_time: 127, checksum: 0x1234)
          expect(igmp.type).to eq(255)
          expect(igmp.max_resp_time).to eq(127)
          expect(igmp.checksum).to eq(0x1234)
        end
      end

      describe '#read' do
        let(:igmp) { IGMPv3.new}

        it 'sets header from a string' do
          str = (1..igmp.sz).to_a.pack('C*') + 'body'
          igmp.read str
          expect(igmp.type).to eq(1)
          expect(igmp.max_resp_time).to eq(2)
          expect(igmp.checksum).to eq(0x0304)
        end

        it 'reads a IGMPv3 header in a real packet' do
          pkt = PacketGen.gen('IP', src: '192.168.0.1', dst: '224.0.0.1',
                              ttl: 1, protocol: 2, tos: 0xc0)
          pkt.body = "\x11\x00\xee\xff"
          parsed_pkt = PacketGen.parse(pkt.to_s)
          expect(parsed_pkt.is? 'IP').to be(true)
          expect(parsed_pkt.is? 'IGMPv3').to be(true)
          expect(parsed_pkt.igmpv3.human_type).to eq('MembershipQuery')
          expect(parsed_pkt.igmpv3.max_resp_time).to eq(0)
        end
      end

      describe '#calc_checksum' do
        it 'computes IGMPv3 header checksum' do
          igmp = IGMPv3.new(type: 0x11, max_resp_time: 20)
          igmp.calc_checksum
          expect(igmp.calc_checksum).to eq(0xeeeb)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          igmp = IGMPv3.new(type: 'MembershipQuery', max_resp_time: 20)
          igmp.calc_checksum
          expected = binary("\x11\x14\xee\xeb")
          expect(igmp.to_s).to eq(expected)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          igmp = IGMPv3.new
          str = igmp.inspect
          expect(str).to be_a(String)
          (igmp.fields - %i(body)).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe '#igmpize' do
        it 'fixup IP header' do
          pkt = PacketGen.gen('IP', src: '75.12.34.56', dst: '224.0.0.1', id: 0)
          pkt.add('IGMPv3', type: 0x11)
          pkt.igmpize
          expect(pkt.ip.tos).to eq(0xc0)
          expect(pkt.ip.ttl).to eq(1)
          expect(pkt.ip.options.size).to eq(1)
          expect(pkt.ip.options[0]).to be_a(IP::RA)
          expected = "\x46\xc0\x00\x1c\x00\x00\x00\x00\x01\x02\xd6\xd6"
          expected << "\x4b\x0c\x22\x38\xe0\x00\x00\x01\x94\x04\x00\x00"
          expected << "\x11\x00\xee\xff"
          expect(pkt.to_s).to eq(binary(expected))
        end
      end

      describe '#max_resp_time' do
        let (:igmp) { IGMPv3.new }

        it 'sets IGMPv3 encoded Max Resp Time' do
          igmp.max_resp_time = 10000
          expect(igmp[:max_resp_time].value).to eq(0xe3)
        end

        it 'gets IGMPv3 encoded Max Resp Time' do
          igmp[:max_resp_time].value = 0xe3
          expect(igmp.max_resp_time).to eq(9728)
        end
      end

      describe '#parse' do
        let(:packets) { PacketGen.read(File.join(__dir__, 'igmpv3.pcapng')) }

        it 'decodes a V3 extended Membership Query' do
          pkt = packets.first
          expect(pkt.is? 'IGMPv3').to be(true)
          expect(pkt.igmpv3.type).to eq(0x11)
          expect(pkt.is? 'IGMPv3::MQ').to be(true)
          expect(pkt.igmpv3_mq.group_addr).to eq('224.0.0.9')
          expect(pkt.igmpv3_mq.u8).to eq(0xf)
          expect(pkt.igmpv3_mq.flag_s?).to be(true)
          expect(pkt.igmpv3_mq.qrv).to eq(7)
          expect(pkt.igmpv3_mq.qqic).to eq(0)
          expect(pkt.igmpv3_mq.number_of_sources).to eq(1)
          expect(pkt.igmpv3_mq.source_addr.size).to eq(1)
          expect(pkt.igmpv3_mq.source_addr.first.to_human).to eq('192.168.20.222')
        end

        it 'decodes a V3 extended Membership Report' do
          pkt = packets.last
          expect(pkt.is? 'IGMPv3').to be(true)
          expect(pkt.igmpv3.type).to eq(0x22)
          expect(pkt.igmpv3.max_resp_code).to eq(0)
          expect(pkt.igmpv3.checksum).to eq(0x276d)
          expect(pkt.is? 'IGMPv3::MR').to be(true)
          expect(pkt.igmpv3_mr.reserved).to eq(0)
          expect(pkt.igmpv3_mr.number_of_gr).to eq(1)
          expect(pkt.igmpv3_mr.group_records.size).to eq(1)
          gr = pkt.igmpv3_mr.group_records.first
          expect(gr).to be_a(IGMPv3::GroupRecord)
          expect(gr.human_type).to eq('MODE_IS_INCLUDE')
          expect(gr.aux_data_len).to eq(0)
          expect(gr.number_of_sources).to eq(1)
          expect(gr.multicast_addr).to eq('224.0.0.9')
          expect(gr.source_addr.size).to eq(1)
          expect(gr.source_addr[0].to_human).to eq('192.168.20.222')
          expect(gr.aux_data).to eq('')
        end
      end
    end
  end
end
