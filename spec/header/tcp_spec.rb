require_relative '../spec_helper'

module PacketGen
  module Header

    describe TCP do
      describe 'binding' do
        it 'in IP packets' do
          expect(IP.known_headers[TCP].to_h).to eq({key: :proto, value: 6})
          expect(IPv6.known_headers[TCP].to_h).to eq({key: :next, value: 6})
        end
      end

      describe '#initialize' do
        it 'creates a TCP header with default values' do
          tcp = TCP.new
          expect(tcp).to be_a(TCP)
          expect(tcp.sport).to eq(0)
          expect(tcp.dport).to eq(0)
          expect(tcp.seq).to_not eq(0)
          expect(tcp.ack).to eq(0)
          expect(tcp.hlen).to eq(5)
          expect(tcp.reserved).to eq(0)
          expect(tcp.flags).to eq(0)
          expect(tcp.wsize).to eq(0)
          expect(tcp.sum).to eq(0)
          expect(tcp.urg).to eq(0)
          expect(tcp.options).to be_empty
          expect(tcp.body).to be_empty
        end

        it 'accepts options' do
          options = {
            sport: 1234,
            dport: 4567,
            seq: 0xff00fe02,
            ack: 0xfedcba98,
            hlen: 15,
            reserved: 5,
            flags: 0x11,
            wsize: 0x5342,
            sum: 0xfedc,
            urg: 0x1234,
            body: 'abcdef'
          }
          tcp = TCP.new(options)

          options.each do |key, value|
            expect(tcp.send(key)).to eq(value)
          end
        end
      end

      describe '#read' do
        let(:tcp) { TCP.new}

        it 'sets header from a string' do
          ary = (0...tcp.sz).to_a
          ary[12] |= 0x50
          str = ary.pack('C*') + 'body'
          tcp.read str
          expect(tcp.sport).to eq(0x0001)
          expect(tcp.dport).to eq(0x0203)
          expect(tcp.seq).to eq(0x04050607)
          expect(tcp.ack).to eq(0x08090a0b)
          expect(tcp.hlen).to eq(5)
          expect(tcp.reserved).to eq(6)
          expect(tcp.flags).to eq(0x0d)
          expect(tcp.wsize).to eq(0x0e0f)
          expect(tcp.sum).to eq(0x1011)
          expect(tcp.urg).to eq(0x1213)
          expect(tcp.options).to be_empty
          expect(tcp.body).to eq('body')
        end

        it 'raises when str is too short' do
          expect { tcp.read 'abcd' }.to raise_error(ParseError, /too short/)
        end
      end

      describe '#calc_sum' do
        it 'computes TCP over IP header checksum' do
          packets = Packet.read(File.join(__dir__, '..', 'pcapng', 'sample.pcapng'))[7, 3]
          packets.each do |pkt|
            sum = pkt.tcp.sum
            pkt.tcp.sum = 0
            expect(pkt.tcp.sum).to_not eq(sum)
            pkt.tcp.calc_sum
            expect(pkt.tcp.sum).to eq(sum)
          end
        end

        it 'computes TCP over IPv6 header checksum' do
          pending 'need options'
          pkt = Packet.read(File.join(__dir__, '..', 'pcapng', 'ipv6_tcp.pcapng'))[1]
          expect(pkt.is? 'IPv6').to be(true)
          sum = pkt.tcp.sum
          pkt.tcp.sum = 0
          expect(pkt.tcp.sum).to_not eq(sum)
          pkt.tcp.calc_sum
          expect(pkt.tcp.sum).to eq(sum)
        end
      end

      describe 'setters' do
        let(:tcp) { TCP.new }
        
        it '#sport= accepts integers' do
          tcp.sport = 145
          expect(tcp[:sport].value).to eq(145)
        end

        it '#dport= accepts integers' do
          tcp.dport = 146
          expect(tcp[:dport].value).to eq(146)
        end

        it '#seq= accepts integers' do
          tcp.seq = 0x5432897b
          expect(tcp[:seq].value).to eq(0x5432897b)
        end

        it '#ack= accepts integers' do
          tcp.ack = 0x5432897c
          expect(tcp[:ack].value).to eq(0x5432897c)
        end

        it '#wsize= accepts integers' do
          tcp.wsize = 60000
          expect(tcp[:wsize].value).to eq(60000)
        end

        it '#sum= accepts integers' do
          tcp.sum = 65500
          expect(tcp[:sum].value).to eq(65500)
        end

        it '#urg= accepts integers' do
          tcp.urg = 37560
          expect(tcp[:urg].value).to eq(37560)
        end

      end

      describe '#to_s' do
        it 'returns a binary string' do
          pending 'need options'
          strings = []
          file = PcapNG::File.new
          strings << file.read_packet_bytes(File.join(__dir__, '..', 'pcapng',
                                                      'sample.pcapng'))[7]
          file.clear
          strings << file.read_packet_bytes(File.join(__dir__, '..', 'pcapng',
                                                      'ipv6_tcp.pcapng'))[1]
          strings.each do |str|
            pkt = Packet.parse(str)
            expect(pkt.to_s).to eq(str)
          end
        end
      end
    end
  end
end
