require_relative '../spec_helper'

module PacketGen
  module Header

    describe IP::Addr do
      before(:each) do
        @ipaddr = IP::Addr.new.from_human('192.168.25.43')
      end

      it '#parse a string containing a dotted address' do
        expect(@ipaddr.a1).to eq(192)
        expect(@ipaddr.a2).to eq(168)
        expect(@ipaddr.a3).to eq(25)
        expect(@ipaddr.a4).to eq(43)
      end

      it '#to_i gets IP address as a 32-bit integer' do
        expect(@ipaddr.to_i).to eq(0xc0a8192b)
      end

      it '#to_human returns a dotted address as String' do
        expect(@ipaddr.to_human).to eq('192.168.25.43')
      end
    end

    describe IP do

      describe 'binding' do
        it 'in Eth packets' do
          expect(Eth).to know_header(IP).with(ethertype: 0x800)
        end
        it 'in SNAP packets' do
          expect(SNAP).to know_header(IP).with(proto_id: 0x800)
        end
        it 'in IP packets' do
          expect(IP).to know_header(IP).with(protocol: 4)
        end
      end

      describe '#initialize' do
        it 'creates a IP header with default values' do
          ip = IP.new
          expect(ip).to be_a(IP)
          expect(ip.version).to eq(4)
          expect(ip.tos).to eq(0)
          expect(ip.length).to eq(20)
          expect(ip.id).to be < 65536
          expect(ip.frag).to eq(0)
          expect(ip.ttl).to eq(64)
          expect(ip.protocol).to eq(0)
          expect(ip.checksum).to eq(0)
          expect(ip.src).to eq('127.0.0.1')
          expect(ip.dst).to eq('127.0.0.1')
          expect(ip.body).to eq('')
        end

        it 'accepts options' do
          options = {
            version: 0xf,
            ihl: 0xf,
            tos: 255,
            length: 1000,
            id: 153,
            frag: 0x4000,
            ttl: 2,
            protocol: 250,
            checksum: 1,
            src: '1.1.1.1',
            dst: '2.2.2.2',
            body: 'this is a body'
          }
          ip = IP.new(options)
          options.each do |key, value|
            expect(ip.send(key)).to eq(value)
          end
        end
      end

      describe '#read' do
        let(:ip) { IP.new}

        it 'sets header from a string' do
          str = (1..ip.sz).to_a.pack('C*') + 'body'
          ip.read str
          expect(ip.version).to eq(0)
          expect(ip.ihl).to eq(1)
          expect(ip.tos).to eq(2)
          expect(ip.length).to eq(0x0304)
          expect(ip.id).to eq(0x0506)
          expect(ip.frag).to eq(0x0708)
          expect(ip.ttl).to eq(9)
          expect(ip.protocol).to eq(10)
          expect(ip.checksum).to eq(0x0b0c)
          expect(ip.src).to eq('13.14.15.16')
          expect(ip.dst).to eq('17.18.19.20')
          expect(ip.options).to eq([])
          expect(ip.body).to eq('body')
        end

        it 'reads a IP header with options' do
          pkt = PacketGen.read(File.join(__dir__, 'ip_opts.pcapng')).first
          expect(pkt.is? 'IP').to be(true)

          ip = pkt.ip
          expect(ip.ihl).to eq(11)
          expect(ip).to respond_to(:options)
          expect(ip.options.sz).to eq(24)
          expect(ip.body).to be_a(Header::ICMP)

          raw_pkt = PacketGen.gen('IP', src: '192.168.0.1', dst: '192.168.1.2', ihl: 9, protocol: 254).to_s
          raw_pkt << PacketGen.force_binary("\x01\x83\x07\x04\xc0\xa8\x00\xfe")
          raw_pkt << PacketGen.force_binary("\x88\x04\x01\x02\x94\x04\x00\x00")
          raw_pkt << 'body'
          pkt = PacketGen.parse(raw_pkt, first_header: 'IP')
          expect(pkt.ip.ihl).to eq(9)
          expect(pkt.ip.options.size).to eq(4)
          expect(pkt.ip.options.sz).to eq(16)
          expect(pkt.ip.options[0]).to be_a(IP::NOP)
          expect(pkt.ip.options[1]).to be_a(IP::LSRR)
          expect(pkt.ip.options[1].data[0].to_human).to eq('192.168.0.254')
          expect(pkt.ip.options[2]).to be_a(IP::SI)
          expect(pkt.ip.options[2].id).to eq(0x102)
          expect(pkt.ip.options[3]).to be_a(IP::RA)
        end
      end

      describe '#calc_checksum' do
        it 'compute IP header checksum' do
          ip = IP.new(length: 60, id: 0x1c46, frag: 0x4000, ttl: 64, protocol: 6,
                      src: '172.16.10.99', dst: '172.16.10.12')
          ip.calc_checksum
          expect(ip.checksum).to eq(0xb1e6)
        end
      end

      describe 'setters' do
        before(:each) do
          @ip = IP.new
        end

        it '#tos= accepts integers' do
          @ip.tos = 254
          expect(@ip[:tos].to_i).to eq(254)
        end

        it '#length= accepts integers' do
          @ip.length = 0xff10
          expect(@ip[:length].to_i).to eq(0xff10)
        end

        it '#id= accepts integers' do
          @ip.id = 0x8001
          expect(@ip[:id].to_i).to eq(0x8001)
        end

        it '#frag= accepts integers' do
          @ip.frag = 0x4001
          expect(@ip[:frag].to_i).to eq(0x4001)
        end

        it '#ttl= accepts integers' do
          @ip.ttl = 255
          expect(@ip[:ttl].to_i).to eq(255)
        end

        it '#protocol= accepts integers' do
          @ip.protocol = 255
          expect(@ip[:protocol].to_i).to eq(255)
        end

        it '#checksum= accepts integers' do
          @ip.checksum = 0xf00f
          expect(@ip[:checksum].to_i).to eq(0xf00f)
        end

        it '#src= accepts dotted addresses' do
          @ip.src = '1.2.3.4'
          1.upto(4) do |i|
            expect(@ip[:src]["a#{i}".to_sym].to_i).to eq(i)
          end
          expect(@ip[:src].to_i).to eq(0x01020304)
        end

        it '#dst= accepts dotted addresses' do
          @ip.dst = '1.2.3.4'
          1.upto(4) do |i|
            expect(@ip[:dst]["a#{i}".to_sym].to_i).to eq(i)
          end
          expect(@ip[:dst].to_i).to eq(0x01020304)
        end
      end

      describe '#to_w' do
        it 'responds to #to_w' do
          expect(IP.new).to respond_to(:to_w)
        end

        it 'sends a IP header on wire', :sudo do
          body = PacketGen.force_binary("\x00" * 64)
          pkt = Packet.gen('IP').add('UDP', sport: 35535, dport: 65535, body: body)
          pkt.calc
          Thread.new { sleep 0.1; pkt.ip.to_w('lo') }
          packets = Packet.capture(iface: 'lo', max: 1,
                                   filter: 'ip dst 127.0.0.1 and ip proto 17',
                                   timeout: 2)
          packet = packets.first
          expect(packet.is? 'IP').to be(true)
          expect(packet.ip.dst).to eq('127.0.0.1')
          expect(packet.ip.src).to eq('127.0.0.1')
          expect(packet.ip.protocol).to eq(UDP::IP_PROTOCOL)
          expect(packet.udp.sport).to eq(35535)
          expect(packet.udp.dport).to eq(65535)
          expect(packet.body).to eq(body)
        end
      end
    end

    describe '#to_s' do
      it 'returns a binary string' do
        ip = IP.new
        idx = [ip.id].pack('n')
        expected = "\x45\x00\x00\x14#{idx}\x00\x00\x40\x00\x00\x00" \
                   "\x7f\x00\x00\x01\x7f\x00\x00\x01"
        expect(ip.to_s).to eq(PacketGen.force_binary expected)
      end
    end

    describe '#inspect' do
      it 'returns a String with all attributes' do
        ip = IP.new
        str = ip.inspect
        expect(str).to be_a(String)
        (ip.to_h.keys - %i(body) + %i(version ihl flags frag_offset)).each do |attr|
          expect(str).to include(attr.to_s)
        end
      end
    end

    context 'frag field' do
      let(:ip) { IP.new }

      it 'may be accessed through flag_rsv' do
        expect(ip.flag_rsv?).to be(false)
        ip.frag = 0x8000
        expect(ip.flag_rsv?).to be(true)
        ip.flag_rsv = false
        expect(ip.frag).to eq(0)
      end

      it 'may be accessed through flag_df' do
        expect(ip.flag_df?).to be(false)
        ip.frag = 0x4000
        expect(ip.flag_df?).to be(true)
        ip.flag_df = false
        expect(ip.frag).to eq(0)
      end

      it 'may be accessed through flag_mf' do
        expect(ip.flag_mf?).to be(false)
        ip.frag = 0x2000
        expect(ip.flag_mf?).to be(true)
        ip.flag_mf = false
        expect(ip.frag).to eq(0)
      end

      it 'may be accessed through fragment_offset' do
        expect(ip.fragment_offset).to eq(0)
        ip.frag = 0x1025
        expect(ip.fragment_offset).to eq(0x1025)
        ip.fragment_offset = 0x1001
        ip.flag_rsv = true
        expect(ip.frag).to eq(0x9001)
      end
    end
  end
end
