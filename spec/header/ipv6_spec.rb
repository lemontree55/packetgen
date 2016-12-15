require_relative '../spec_helper'

module PacketGen
  module Header

    describe IPv6::Addr do
      before(:each) do
        @ipv6addr = IPv6::Addr.new.parse('fe80::21a:c5ff:fe00:152')
      end

      it '#parse a string containing a dotted address' do
        expect(@ipv6addr.a1).to eq(0xfe80)
        expect(@ipv6addr.a2).to eq(0)
        expect(@ipv6addr.a3).to eq(0)
        expect(@ipv6addr.a4).to eq(0)
        expect(@ipv6addr.a5).to eq(0x021a)
        expect(@ipv6addr.a6).to eq(0xc5ff)
        expect(@ipv6addr.a7).to eq(0xfe00)
        expect(@ipv6addr.a8).to eq(0x0152)
      end

      it '#to_x returns a dotted address as String' do
        expect(@ipv6addr.to_x).to eq('fe80::21a:c5ff:fe00:152')
      end

      it '#read gets a IPv6 address from a binary string' do
        bin_str = "\xfe\x80" << "\x00" * 6 << "\x02\x1a\xc5\xff\xfe\x00\x01\x52"
        ipv6addr = IPv6::Addr.new.read(bin_str)
        expect(ipv6addr.to_x).to eq('fe80::21a:c5ff:fe00:152')
      end
    end

    describe IPv6 do

      describe 'binding' do
        it 'in Eth packets' do
          expect(Eth.known_headers[IPv6].to_h).to eq({key: :ethertype, value: 0x86dd})
        end
        it 'in IP packets' do
          expect(IP.known_headers[IPv6].to_h).to eq({key: :protocol, value: 41})
        end
      end

      describe '#initialize' do
        it 'creates a IPv6 header with default values' do
          ipv6 = IPv6.new
          expect(ipv6).to be_a(IPv6)
          expect(ipv6.version).to eq(6)
          expect(ipv6.traffic_class).to eq(0)
          expect(ipv6.flow_label).to eq(0)
          expect(ipv6.length).to eq(0)
          expect(ipv6.next).to eq(0)
          expect(ipv6.hop).to eq(64)
          expect(ipv6.src).to eq('::1')
          expect(ipv6.dst).to eq('::1')
          expect(ipv6.body).to eq('')
        end

        it 'accepts options' do
          options = {
            version: 15,
            traffic_class: 128,
            flow_label: 0x851ec,
            length: 10_000,
            next: 250,
            hop: 129,
            src: '2000::1',
            dst: '2001:1234:5678:9abc:def0:fedc:ba98:7654',
            body: 'this is a body'
          }
          ipv6 = IPv6.new(options)
          options.each do |key, value|
            expect(ipv6.send(key)).to eq(value)
          end
        end
      end

      describe '#read' do
        let(:ipv6) { IPv6.new}

        it 'sets header from a string' do
          str = (1..ipv6.sz).to_a.pack('C*') + 'body'
          ipv6.read str
          expect(ipv6.version).to eq(0)
          expect(ipv6.traffic_class).to eq(0x10)
          expect(ipv6.flow_label).to eq(0x20304)
          expect(ipv6.length).to eq(0x0506)
          expect(ipv6.next).to eq(7)
          expect(ipv6.hop).to eq(8)
          expect(ipv6.src).to eq('90a:b0c:d0e:f10:1112:1314:1516:1718')
          expect(ipv6.dst).to eq('191a:1b1c:1d1e:1f20:2122:2324:2526:2728')
          expect(ipv6.body).to eq('body')
        end

        it 'raises when str is too short' do
          expect { ipv6.read 'abcd' }.to raise_error(ParseError, /too short/)
          expect { ipv6.read('a' * 39) }.to raise_error(ParseError, /too short/)
        end
      end

        describe '#calc_length' do
          it 'computes IPv6 length field' do
            ipv6 = IPv6.new
            body = (0...rand(60_000)).to_a.pack('C*')
            ipv6.body = body
            ipv6.calc_length
            expect(ipv6.length).to eq(body.size)
          end

          it 'computes IPv6 length field when IPv6 body is another protocol' do
            pkt = Packet.gen('IPv6').add('UDP')
            body = (0...rand(60_000)).to_a.pack('C*')
            pkt.body = body
            pkt.ipv6.calc_length
            expect(pkt.ipv6.length).to eq(body.size + UDP.new.sz)
          end
        end

        describe 'setters' do
          before(:each) do
            @ipv6 = IPv6.new
          end

          it '#length= accepts integers' do
            @ipv6.length = 65530
            expect(@ipv6[:length].to_i).to eq(65530)
          end

          it '#next= accepts integers' do
            @ipv6.next = 65530
            expect(@ipv6[:next].to_i).to eq(65530)
          end

          it '#hop= accepts integers' do
            @ipv6.hop = 65530
            expect(@ipv6[:hop].to_i).to eq(65530)
          end

          it '#src= accepts integers' do
            @ipv6.src = '1:2:3:4:5:6:7:8'
            1.upto(8) do |i|
              expect(@ipv6[:src]["a#{i}".to_sym].to_i).to eq(i)
            end
          end

          it '#dst= accepts integers' do
            @ipv6.dst = '1:2:3:4:5:6:7:8'
            1.upto(8) do |i|
              expect(@ipv6[:dst]["a#{i}".to_sym].to_i).to eq(i)
            end
          end
        end

        describe '#to_w' do
          it 'responds to #to_w' do
            expect(IPv6.new).to respond_to(:to_w)
          end

          it 'sends a IPv6 header on wire', :sudo, :notravis do
            body = PacketGen.force_binary("\x00" * 64)
            pkt = Packet.gen('IPv6', traffic_class: 0x40, hop: 0x22, src: '::1').
                  add('UDP', sport: 35535, dport: 65535, body: body)
            pkt.calc
            Thread.new { sleep 1; pkt.ipv6.to_w('lo') }
            packets = Packet.capture('lo', max: 1,
                                     filter: 'ip6 dst ::1',
                                     timeout: 4)
            packet = packets.first
            expect(packet.is? 'IPv6').to be(true)
            expect(packet.ipv6.dst).to eq('::1')
            expect(packet.ipv6.src).to eq('::1')
            expect(packet.ipv6.next).to eq(UDP::IP_PROTOCOL)
            expect(packet.ipv6.traffic_class).to eq(0x40)
            expect(packet.ipv6.hop).to eq(0x22)
            expect(packet.udp.sport).to eq(35535)
            expect(packet.udp.dport).to eq(65535)
            expect(packet.body).to eq(body)
          end
        end

       it '#to_s returns a binary string' do
          ipv6 = IPv6.new
          ipv6.body = 'body'
          ipv6.calc_length
          expected = "\x60\x00\x00\x00\x00\x04\x00\x40"
          expected << ("\x00" * 15 + "\x01") * 2 << 'body'
          PacketGen.force_binary expected
          expect(ipv6.to_s).to eq(expected)
        end
     end
  end
end
