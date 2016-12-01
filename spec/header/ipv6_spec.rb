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
          expect(Eth.known_headers[IPv6].to_h).to eq({key: :proto, value: 0x86dd})
        end
        it 'in IP packets' do
          expect(IP.known_headers[IPv6].to_h).to eq({key: :proto, value: 41})
        end
      end

      describe '#initialize' do
        it 'creates a IPv6 header with default values' do
          ipv6 = IPv6.new
          expect(ipv6).to be_a(IPv6)
          expect(ipv6.version).to eq(6)
          expect(ipv6.traffic_class).to eq(0)
          expect(ipv6.flow_label).to eq(0)
          expect(ipv6.length).to eq(40)
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
            flow_label: 0xf851ec,
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
          pending
          str = (1..ipv6.sz).to_a.pack('C*') + 'body'
          ipv6.read str
          expect(ipv6.version).to eq(0)
          expect(ipv6.ihl).to eq(1)
          expect(ipv6.tos).to eq(2)
          expect(ipv6.len).to eq(0x0304)
          expect(ipv6.id).to eq(0x0506)
          expect(ipv6.frag).to eq(0x0708)
          expect(ipv6.ttl).to eq(9)
          expect(ipv6.proto).to eq(10)
          expect(ipv6.sum).to eq(0x0b0c)
          expect(ipv6.src).to eq('13.14.15.16')
          expect(ipv6.dst).to eq('17.18.19.20')
          expect(ipv6.body).to eq('body')
        end

        it 'raises when str is too short' do
          pending
          expect { ipv6.read 'abcd' }.to raise_error(ParseError, /too short/)
          expect { ipv6.read('a' * 18) }.to raise_error(ParseError, /too short/)
        end
      end

        describe '#calc_length' do
          it 'compute IPv6 length field' do
            pending
            ipv6 = IPv6.new(len: 60, id: 0x1c46, frag: 0x4000, ttl: 64, proto: 6,
                        src: '172.16.10.99', dst: '172.16.10.12')
            ipv6.calc_sum
            expect(ipv6.sum).to eq(0xb1e6)
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

        it '#to_s returns a binary string' do
          ipv6 = IPv6.new
          expected = "\x60\x00\x00\x00\x00\x28\x00\x40"
          expected << ("\x00" * 15 + "\x01") * 2
          PacketGen.force_binary expected
          expect(ipv6.to_s).to eq(expected)
        end
     end
  end
end
