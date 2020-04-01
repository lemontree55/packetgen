require_relative '../spec_helper'

module PacketGen
  module Header
    module MLDv2
      describe MLQ do
        describe 'bindings' do
          it 'in ICMPv6 packets' do
            expect(ICMPv6).to know_header(MLQ).with(type: 130, body: '0' * 24)
          end
        end

        describe '#initialize' do
          it 'creates a MLDv2 MLQ header with default values' do
            mlq = MLDv2::MLQ.new
            expect(mlq).to be_a(MLD)
            expect(mlq.max_resp_delay).to eq(0)
            expect(mlq.reserved).to eq(0)
            expect(mlq.mcast_addr).to eq('::')
            expect(mlq.flags).to eq(0)
            expect(mlq.qqic).to eq(0)
            expect(mlq.number_of_sources).to eq(0)
            expect(mlq.source_addr).to eq([])
          end

          it 'accepts options' do
            mlq = MLDv2::MLQ.new(max_resp_delay: 254, reserved: 0x1234,
                                 mcast_addr: '::', qqic: 127)
            expect(mlq.max_resp_delay).to eq(254)
            expect(mlq.reserved).to eq(0x1234)
            expect(mlq.mcast_addr).to eq('::')
            expect(mlq.qqic).to eq(127)
          end
        end

        describe '#read' do
          let(:mlq) { MLDv2::MLQ.new}

          it 'sets header from a string' do
            str = (1..mlq.sz).to_a.pack('C*')
            mlq.read str
            expect(mlq.max_resp_delay).to eq(0x102)
            expect(mlq.reserved).to eq(0x304)
            expect(mlq.mcast_addr).to eq('506:708:90a:b0c:d0e:f10:1112:1314')
            expect(mlq.flags).to eq(0x15)
            expect(mlq.qqic).to eq(0x16)
            expect(mlq.number_of_sources).to eq(0x1718)
          end

          it 'reads a MLDv2 MLQ header from a real packet' do
            pkt = PacketGen.gen('IPv6', src: 'fe80::1', dst: 'ff02::1', hop: 1).
                            add('IPv6::HopByHop').
                            add('ICMPv6', type: 130, code: 0)
            pkt.ipv6_hopbyhop.options << { type: 'router_alert', value: Types::Int16.new(0).to_s }
            pkt.body = "\x00\x7f\x00\x00" + ([0] * 16).pack('C*') +
                       [1, 0x2000, 0, 0, 0, 0, 0, 0, 1].pack('Nn*')
            pkt.calc
            parsed_pkt = PacketGen.parse(pkt.to_s)
            expect(parsed_pkt.is? 'IPv6').to be(true)
            expect(parsed_pkt.is? 'ICMPv6').to be(true)
            expect(parsed_pkt.is? 'MLDv2::MLQ').to be(true)
            expect(parsed_pkt.mldv2_mlq.max_resp_delay).to eq(127)
            expect(parsed_pkt.mldv2_mlq.reserved).to eq(0)
            expect(parsed_pkt.mldv2_mlq.mcast_addr).to eq('::')
            expect(parsed_pkt.mldv2_mlq.flags).to eq(0)
            expect(parsed_pkt.mldv2_mlq.qqic).to eq(0)
            expect(parsed_pkt.mldv2_mlq.number_of_sources).to eq(1)
            expect(parsed_pkt.mldv2_mlq.source_addr.size).to eq(1)
            src = parsed_pkt.mldv2_mlq.source_addr.first
            expect(src.to_human).to eq('2000::1')
          end

          it 'reads a MLDv2 MLQ header from a pcap' do
            pkt = PacketGen.read(File.join(__dir__, 'mldv2.pcapng'))[1]
            expect(pkt.is? 'MLDv2::MLQ').to be(true)
            mlq = pkt.mldv2_mlq
            expect(mlq.max_resp_code).to eq(0)
            expect(mlq.mcast_addr).to eq('ff02::1')
            expect(mlq.flags).to eq(0)
            expect(mlq.qqic).to eq(0)
            expect(mlq.number_of_sources).to eq(8)
            expect(mlq.source_addr.size).to eq(8)
            sources = mlq.source_addr.map(&:to_human)
            expect(sources).to eq(['::', 'ff02::1', '::',
                                   'ff02::1', 'ff02::1', 'ff02::2',
                                   '::1', 'ff02::1:ff00:9'])
          end
        end

        describe '#max_resp_delay' do
          let(:mlq) { MLDv2::MLQ.new }

          it 'sets encoded Max Resp Code' do
            [1, 1000, 32767].each do |value|
              mlq.max_resp_delay = value
              expect(mlq.max_resp_code).to eq(value)
            end
            mlq.max_resp_delay = 32768
            expect(mlq.max_resp_code).to eq(0x8000)
            mlq.max_resp_delay = 8_387_583
            expect(mlq.max_resp_code).to eq(0xfffe)
            [8_387_584, 10_000_000].each do |value|
              mlq.max_resp_delay = value
              expect(mlq.max_resp_code).to eq(0xffff)
            end
          end

          it 'gets decoded Max Resp Delay' do
            [1, 1000, 32767].each do |value|
              mlq.max_resp_code = value
              expect(mlq.max_resp_delay).to eq(value)
            end
            mlq.max_resp_code = 0x8000
            expect(mlq.max_resp_delay).to eq(32768)
            mlq.max_resp_code = 0xfffe
            expect(mlq.max_resp_delay).to eq(8_386_560)
            mlq.max_resp_code = 0xffff
            expect(mlq.max_resp_delay).to eq(8_387_584)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            mlq = MLDv2::MLQ.new(max_resp_delay: 20,
                                mcast_addr: 'ff02::1')
            mlq.source_addr << '2000::1'
            expected = "\x00\x14\x00\x00"
            expected << [0xff02, 0, 0, 0, 0, 0, 0, 1].pack('n*')
            expected << [1, 0x2000, 0, 0, 0, 0, 0, 0, 1].pack('Nn*')
            expect(mlq.to_s).to eq(expected)
          end
        end

        describe '#inspect' do
          it 'returns a String with all attributes' do
            mlq = MLDv2::MLQ.new
            str = mlq.inspect
            expect(str).to be_a(String)
            (mlq.fields - %i(body)).each do |attr|
              expect(str).to include(attr.to_s)
            end
          end
        end
      end

      describe MLR do
        describe 'bindings' do
          it 'in ICMPv6 packets' do
            expect(ICMPv6).to know_header(MLR).with(type: 143)
          end
        end

        describe '#read' do
          it 'parses a MLDv2::MLR packet' do
            pkt = PacketGen.read(File.join(__dir__, 'mldv2.pcapng'))[0]
            expect(pkt.is? 'ICMPv6').to be(true)
            expect(pkt.is? 'MLDv2::MLR').to be(true)
            expect(pkt.mldv2_mlr.number_of_mar).to eq(1)
            expect(pkt.mldv2_mlr.records.size).to eq(1)
            mar = pkt.mldv2_mlr.records.first
            expect(mar.type).to eq(1)
            expect(mar.human_type).to eq('MODE_IS_INCLUDE')
            expect(mar.aux_data_len).to eq(2)
            expect(mar.aux_data.size).to eq(8)
            expect(mar.aux_data).to eq(force_binary("\xde\xad\xbe\xef\xbe\xad\xfe\xed"))
            expect(mar.number_of_sources).to eq(8)
            expect(mar.source_addr.size).to eq(8)
            sources = mar.source_addr.map(&:to_human)
            expect(sources).to eq(['::', 'ff02::1', '::',
                                   'ff02::1', 'ff02::1', 'ff02::2',
                                   '::1', 'ff02::1:ff00:9'])
          end
        end
      end
    end
  end
end
