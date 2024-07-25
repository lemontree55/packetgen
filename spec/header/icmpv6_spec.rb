require_relative '../spec_helper'

module PacketGen
  module Header
    describe ICMPv6 do
      let(:pcapng_file) { File.join(__dir__, '..', 'pcapng', 'icmpv6.pcapng') }

      describe 'bindings' do
        it 'in IP packets' do
          expect(IPv6).to know_header(ICMPv6).with(next: 58)
        end
        it 'accepts to be added in IPv6 packets' do
          pkt = PacketGen.gen('IPv6')
          expect { pkt.add('ICMPv6') }.to_not raise_error
          expect(pkt.ipv6.next).to eq(58)
        end
      end

      describe '#initialize' do
        it 'creates a ICMPv6 header with default values' do
          icmp = ICMPv6.new
          expect(icmp).to be_a(ICMPv6)
          expect(icmp.type).to eq(0)
          expect(icmp.code).to eq(0)
          expect(icmp.checksum).to eq(0)
          expect(icmp.body).to eq('')
        end

        it 'accepts options' do
          icmp = ICMPv6.new(type: 255, code: 254, checksum: 0x1234, body: 'abcd')
          expect(icmp.type).to eq(255)
          expect(icmp.code).to eq(254)
          expect(icmp.checksum).to eq(0x1234)
          expect(icmp.body).to eq('abcd')
        end
      end

      describe '#read' do
        let(:icmp) { ICMPv6.new}

        it 'sets header from a string' do
          str = PcapNG::File.new.read_packet_bytes(pcapng_file).first
          icmp.read str[0x36..-1]
          expect(icmp.type).to eq(135)
          expect(icmp.code).to eq(0)
          expect(icmp.checksum).to eq(0xb867)
          expected = "\0\0\0\0\x2a\x01\x0e\x35\x8b\x7f\x9c\x10\x12\x8b" \
                     "\x3c\x32\xc3\xe4\xc0\x1b\x01\x01\x68\xa3\x78\x03" \
                     "\xcc\xb2"
          expect(icmp.body).to eq(binary expected)
        end
      end

      describe '#calc_checksum' do
        it 'computes ICMPv6 header checksum' do
          packets = Packet.read(pcapng_file)
          packets.each do |pkt|
            checksum = pkt.icmpv6.checksum
            pkt.icmpv6.checksum = 0
            expect(pkt.icmpv6.checksum).to_not eq(checksum)
            pkt.calc
            expect(pkt.icmpv6.checksum).to eq(checksum)
          end
        end
      end

      describe 'setters' do
        let(:icmp) { ICMPv6.new}

        it '#type= accepts integers' do
          icmp.type = 0xef
          expect(icmp[:type].to_i).to eq(0xef)
        end

        it '#code= accepts integers' do
          icmp.code = 0xea
          expect(icmp[:code].to_i).to eq(0xea)
        end

        it '#checksum= accepts integers' do
          icmp.checksum = 0xffff
          expect(icmp[:checksum].to_i).to eq(65535)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          str = PcapNG::File.new.read_packet_bytes(pcapng_file).first
          icmp = Packet.parse(str)
            expect(icmp.to_s).to eq(str)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          icmpv6 = ICMPv6.new
          str = icmpv6.inspect
          expect(str).to be_a(String)
          (icmpv6.attributes - %i(body)).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end
    end
  end
end
