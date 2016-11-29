require_relative '../spec_helper'

module PacketGen
  module Header

    describe UDP do

      describe 'binding' do
        it 'in IP packets' do
          expect(IP.known_headers[UDP].to_h).to eq({key: :proto, value: 17})
        end
      end

      describe '#initialize' do
        it 'creates a UDP header with default values' do
          udp = UDP.new
          expect(udp).to be_a(UDP)
          expect(udp.sport).to eq(0)
          expect(udp.dport).to eq(0)
          expect(udp.length).to eq(8)
          expect(udp.sum).to eq(0)
        end

        it 'accepts options' do
          options = {
            sport: 1234,
            dport: 4567,
            length: 48,
            sum: 0xfedc
          }
          udp = UDP.new(options)

          options.each do |key, value|
            expect(udp.send(key)).to eq(value)
          end
        end

        it 'computes UDP length if length attribute not set' do
          udp = UDP.new(body: 'abcdefghijkl')
          expect(udp.length).to eq(20)
        end
      end

      describe '#calc_sum' do
        it 'computes UDP header checksum' do
          pkt = Packet.gen('IP').add('UDP', sport: 1, dport: 65000)
          pkt.body = 'abcd'
          pkt.calc_length
          pkt.calc_sum
          expect(pkt.udp.sum).to eq(0x3f23)
        end
      end

      describe 'setters' do
        before(:each) do
          @udp = UDP.new
        end

        it '#sport= accepts integers' do
          @udp.sport = 145
          expect(@udp[:sport].value).to eq(145)
        end

        it '#dport= accepts integers' do
          @udp.dport = 146
          expect(@udp[:dport].value).to eq(146)
        end

        it '#length= accepts integers' do
          @udp.length = 0xff0f
          expect(@udp[:length].value).to eq(0xff0f)
        end

        it '#sum= accepts integers' do
          @udp.sum = 0x8001
          expect(@udp[:sum].value).to eq(0x8001)
        end
      end

      it '#to_s returns a binary string' do
        udp = UDP.new(body: [0, 1, 2, 3].pack('C*'))
        udp.calc_length
        expected_str = "\x00" * 4 + "\x00\x0c\x00\x00\x00\x01\x02\x03"
        expect(udp.to_s).to eq(PacketGen.force_binary expected_str)
      end
    end
  end
end
