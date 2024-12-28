# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module Header
    describe TCP do
      describe 'binding' do
        it 'in IP packets' do
          expect(IP).to know_header(TCP).with(protocol: 6)
          expect(IPv6).to know_header(TCP).with(next: 6)
        end

        it 'accepts to be added in IP packets' do
          pkt = PacketGen.gen('IP')
          expect { pkt.add('TCP') }.not_to raise_error
          expect(pkt.ip.protocol).to eq(6)
        end

        it 'accepts to be added in IPv6 packets' do
          pkt = PacketGen.gen('IPv6')
          expect { pkt.add('TCP') }.not_to raise_error
          expect(pkt.ipv6.next).to eq(6)
        end
      end

      describe '#initialize' do
        it 'creates a TCP header with default values' do
          tcp = TCP.new
          expect(tcp).to be_a(TCP)
          expect(tcp.sport).to eq(0)
          expect(tcp.dport).to eq(0)
          expect(tcp.seqnum).not_to eq(0)
          expect(tcp.acknum).to eq(0)
          expect(tcp.hlen).to eq(5)
          expect(tcp.reserved).to eq(0)
          expect(tcp.flags).to eq(0)
          expect(tcp.window).to eq(0)
          expect(tcp.checksum).to eq(0)
          expect(tcp.urg_pointer).to eq(0)
          expect(tcp.options).to be_empty
          expect(tcp.body).to be_empty
        end

        it 'accepts options' do
          options = {
            sport: 1234,
            dport: 4567,
            seqnum: 0xff00fe02,
            acknum: 0xfedcba98,
            data_offset: 15,
            reserved: 5,
            flags: 0x11,
            window: 0x5342,
            checksum: 0xfedc,
            urg_pointer: 0x1234,
            body: 'abcdef'
          }
          tcp = TCP.new(options)

          options.each do |key, value|
            expect(tcp.send(key)).to eq(value)
          end
        end
      end

      describe '#read' do
        let(:tcp) { TCP.new }

        it 'sets header from a string' do
          ary = (0...tcp.sz).to_a
          ary[12] |= 0x50
          str = ary.pack('C*') << 'body'
          tcp.read str
          expect(tcp.sport).to eq(0x0001)
          expect(tcp.dport).to eq(0x0203)
          expect(tcp.seqnum).to eq(0x04050607)
          expect(tcp.acknum).to eq(0x08090a0b)
          expect(tcp.hlen).to eq(5)
          expect(tcp.reserved).to eq(6)
          expect(tcp.flags).to eq(0x0d)
          expect(tcp.window).to eq(0x0e0f)
          expect(tcp.checksum).to eq(0x1011)
          expect(tcp.urg_pointer).to eq(0x1213)
          expect(tcp.options).to be_empty
          expect(tcp.body).to eq('body')
        end
      end

      describe '#calc_checksum' do
        it 'computes TCP over IP header checksum' do
          packets = Packet.read(File.join(__dir__, '..', 'pcapng', 'sample.pcapng'))[7, 3]
          packets.each do |pkt|
            checksum = pkt.tcp.checksum
            pkt.tcp.checksum = 0
            expect(pkt.tcp.checksum).not_to eq(checksum)
            pkt.tcp.calc_checksum
            expect(pkt.tcp.checksum).to eq(checksum)
          end
        end

        it 'computes TCP over IPv6 header checksum' do
          pkt = Packet.read(File.join(__dir__, '..', 'pcapng', 'ipv6_tcp.pcapng'))[1]
          expect(pkt.is?('IPv6')).to be(true)
          checksum = pkt.tcp.checksum
          pkt.tcp.checksum = 0
          expect(pkt.tcp.checksum).not_to eq(checksum)
          pkt.tcp.calc_checksum
          expect(pkt.tcp.checksum).to eq(checksum)
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

        it '#seqnum= accepts integers' do
          tcp.seqnum = 0x5432897b
          expect(tcp[:seqnum].value).to eq(0x5432897b)
        end

        it '#acknum= accepts integers' do
          tcp.acknum = 0x5432897c
          expect(tcp[:acknum].value).to eq(0x5432897c)
        end

        it '#window= accepts integers' do
          tcp.window = 60_000
          expect(tcp[:window].value).to eq(60_000)
        end

        it '#checksum= accepts integers' do
          tcp.checksum = 65_500
          expect(tcp[:checksum].value).to eq(65_500)
        end

        it '#urg_pointer= accepts integers' do
          tcp.urg_pointer = 37_560
          expect(tcp[:urg_pointer].value).to eq(37_560)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
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

      describe '#inspect' do
        it 'returns a String with all attributes' do
          tcp = TCP.new
          str = tcp.inspect
          expect(str).to be_a(String)
          (tcp.attributes - %i[body] + %i[data_offset reserved flags]).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      context 'with flags field' do
        let(:tcp) { TCP.new }

        it 'may be accessed through all flag_* methods' do
          all_flags = (%i[flag_ns flag_cwr flag_ece flag_urg flag_ack flag_psh] +
                       %i[flag_rst flag_syn flag_fin]).reverse
          8.downto(0) do |i|
            expect(tcp.send(:"#{all_flags[i]}?")).to be(false)
            tcp.flags = 1 << i
            expect(tcp.send(:"#{all_flags[i]}?")).to be(true)
            tcp.send :"#{all_flags[i]}=", false
            expect(tcp.flags).to eq(0)
          end

          tcp.flags = 0x155
          9.times { |i| expect(tcp.send(:"#{all_flags[i]}?")).to be(i.even?) }
        end
      end
    end
  end
end
