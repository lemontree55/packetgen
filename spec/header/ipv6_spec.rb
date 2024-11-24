# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module Header
    describe IPv6::Addr do
      before do
        @ipv6addr = IPv6::Addr.new.from_human('fe80::21a:c5ff:fe00:152')
      end

      it '#parse a string containing a colon-delimited address' do
        expect(@ipv6addr.a1).to eq(0xfe80)
        expect(@ipv6addr.a2).to eq(0)
        expect(@ipv6addr.a3).to eq(0)
        expect(@ipv6addr.a4).to eq(0)
        expect(@ipv6addr.a5).to eq(0x021a)
        expect(@ipv6addr.a6).to eq(0xc5ff)
        expect(@ipv6addr.a7).to eq(0xfe00)
        expect(@ipv6addr.a8).to eq(0x0152)
      end

      it '#to_human returns a colon-delimited address as String' do
        expect(@ipv6addr.to_human).to eq('fe80::21a:c5ff:fe00:152')
      end

      it '#read gets a IPv6 address from a binary string' do
        bin_str = +"\xfe\x80" << "\x00" * 6 << "\x02\x1a\xc5\xff\xfe\x00\x01\x52"
        ipv6addr = IPv6::Addr.new.read(bin_str)
        expect(ipv6addr.to_human).to eq('fe80::21a:c5ff:fe00:152')
      end
    end

    describe IPv6 do
      describe 'binding' do
        it 'in Eth packets' do
          expect(Eth).to know_header(IPv6).with(ethertype: 0x86dd)
        end

        it 'accepts to be added in Eth packets' do
          pkt = PacketGen.gen('Eth')
          expect { pkt.add('IPv6') }.not_to raise_error
          expect(pkt.eth.ethertype).to eq(0x86dd)
        end

        it 'in SNAP packets' do
          expect(SNAP).to know_header(IPv6).with(proto_id: 0x86dd)
        end

        it 'accepts to be added in SNAP packets' do
          pkt = PacketGen.gen('SNAP')
          expect { pkt.add('IPv6') }.not_to raise_error
          expect(pkt.snap.proto_id).to eq(0x86dd)
        end

        it 'in IP packets' do
          expect(IP).to know_header(IPv6).with(protocol: 41)
        end

        it 'accepts to be added in IP packets' do
          pkt = PacketGen.gen('IP')
          expect { pkt.add('IPv6') }.not_to raise_error
          expect(pkt.ip.protocol).to eq(41)
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
        let(:ipv6) { IPv6.new }

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

        it 'parses IPv6 extension headers' do
          pkt = PacketGen.read(File.join(__dir__, 'mldv2.pcapng'))[0]
          expect(pkt.is?('IPv6')).to be(true)
          expect(pkt.is?('ICMPv6')).to be(true)
          expect(pkt.is?('IPv6::HopByHop')).to be(true)
          expect(pkt.ipv6_hopbyhop.options.size).to eq(11)
          ra = pkt.ipv6_hopbyhop.options[6]
          expect(ra.human_type).to eq('router_alert')
          expect(ra.value).to eq("\x00\x00")
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
        before do
          @ipv6 = IPv6.new
        end

        it '#length= accepts integers' do
          @ipv6.length = 65_530
          expect(@ipv6[:length].to_i).to eq(65_530)
        end

        it '#next= accepts integers' do
          @ipv6.next = 65_530
          expect(@ipv6[:next].to_i).to eq(65_530)
        end

        it '#hop= accepts integers' do
          @ipv6.hop = 65_530
          expect(@ipv6[:hop].to_i).to eq(65_530)
        end

        it '#src= accepts integers' do
          @ipv6.src = '1:2:3:4:5:6:7:8'
          1.upto(8) do |i|
            expect(@ipv6[:src][:"a#{i}"].to_i).to eq(i)
          end
        end

        it '#dst= accepts integers' do
          @ipv6.dst = '1:2:3:4:5:6:7:8'
          1.upto(8) do |i|
            expect(@ipv6[:dst][:"a#{i}"].to_i).to eq(i)
          end
        end
      end

      describe '#to_w' do
        it 'responds to #to_w' do
          expect(IPv6.new).to respond_to(:to_w)
        end

        it 'sends a IPv6 header on wire', :notravis, :sudo do
          body = (0..63).to_a.pack('C*')
          pkt = Packet.gen('IPv6', traffic_class: 0x40, flow_label: 0x12345, hop: 0x22, src: '::2')
                      .add('UDP', sport: 35_535, dport: 65_535, body: body)
          Thread.new do
            sleep 0.1
            pkt.ipv6.to_w('lo')
          end
          packets = PacketGen.capture(iface: 'lo', max: 1,
                                      filter: 'ip6 dst ::1 and ip6 proto 17',
                                      timeout: 2)
          packet = packets.first
          expect(packet.is?('IPv6')).to be(true)
          expect(packet.ipv6.traffic_class).to eq(0x40)
          expect(packet.ipv6.flow_label).to eq(0x12345)
          expect(packet.ipv6.length).to eq(0)
          expect(packet.ipv6.next).to eq(UDP::IP_PROTOCOL)
          expect(packet.ipv6.hop).to eq(0x22)
          expect(packet.ipv6.dst).to eq('::1')
          expect(packet.ipv6.src).to eq('::2')
          expect(packet.udp.sport).to eq(35_535)
          expect(packet.udp.dport).to eq(65_535)
          expect(packet.body).to eq(body)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          ipv6 = IPv6.new
          ipv6.body = 'body'
          ipv6.calc_length
          expected = +"\x60\x00\x00\x00\x00\x04\x00\x40"
          expected << ("\x00" * 15 << "\x01") * 2 << 'body'
          binary expected
          expect(ipv6.to_s).to eq(expected)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          ip = IPv6.new
          str = ip.inspect
          expect(str).to be_a(String)
          (ip.attributes - %i[body] + %i[version tclass flow_label]).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end
    end
  end
end
