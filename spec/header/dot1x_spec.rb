require_relative '../spec_helper'

module PacketGen
  module Header

    describe Dot1x do
      describe 'binding' do
        it 'in Eth packets' do
          expect(Eth).to know_header(Dot1x).with(ethertype: 0x888e)
        end
      end

      describe '#initialize' do
        it 'creates a Dot1x header with default values' do
          ip = Dot1x.new
          expect(ip).to be_a(Dot1x)
          expect(ip.version).to eq(1)
          expect(ip.type).to eq(0)
          expect(ip.length).to eq(0)
          expect(ip.body).to eq('')
        end

        it 'accepts options' do
          options = {
            version: 0xf5,
            type: 0x81,
            length: 1000,
            body: 'this is a body'
          }
          ip = Dot1x.new(options)
          options.each do |key, value|
            expect(ip.send(key)).to eq(value)
          end
        end

        describe '#read' do
          let(:dot1x) { Dot1x.new }

          it 'sets header from a string' do
            str = (1..dot1x.sz).to_a.pack('C*') + 'body'
            dot1x.read str
            expect(dot1x.version).to eq(1)
            expect(dot1x.type).to eq(2)
            expect(dot1x.length).to eq(0x0304)
            expect(dot1x.body).to eq('body')
          end

          it 'decodes a complex string' do
            packets = read_packets('dot1x.pcapng')
            expect(packets[0].is? 'Dot1x').to be(true)
            expect(packets[0].dot1x.type).to eq(1)
            expect(packets[0].dot1x.human_type).to eq('Start')
            expect(packets[0].dot1x.length).to eq(0)
            expect(packets[2].dot1x.type).to eq(0)
            expect(packets[2].dot1x.human_type).to eq('EAP Packet')
            expect(packets[2].dot1x.length).to eq(19)
            expect(packets[2].dot1x.body.to_s[0..3]).to eq("\x02\x01\x00\x13")
          end
          
          it 'only parses Dot1x data, and no Ethernet padding' do
            pkt = read_packets('dot1x.pcapng')[3]
            expect(pkt.to_s.size).to eq(24)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            dot1x = Dot1x.new
            expected = "\x01\x00\x00\x00"
            expect(dot1x.to_s).to eq(PacketGen.force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a String with all attributes' do
            dot1x = Dot1x.new
            str = dot1x.inspect
            expect(str).to be_a(String)
            (dot1x.to_h.keys - %i(body)).each do |attr|
              expect(str).to include(attr.to_s)
            end
          end
        end
      end
    end
  end
end
