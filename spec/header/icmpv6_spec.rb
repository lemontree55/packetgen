require_relative '../spec_helper'

module PacketGen
  module Header

    describe ICMPv6 do
      let(:pcapng_file) { File.join(__dir__, '..', 'pcapng', 'icmpv6.pcapng') }

      describe 'bindings' do
        it 'in IP packets' do
          expect(IPv6.known_headers[ICMPv6].to_h).to eq({ key: :next, value: 58 })
        end

        describe '#initialize' do
          it 'creates a ICMPv6 header with default values' do
            icmp = ICMPv6.new
            expect(icmp).to be_a(ICMPv6)
            expect(icmp.type).to eq(0)
            expect(icmp.code).to eq(0)
            expect(icmp.sum).to eq(0)
            expect(icmp.body).to eq('')
          end

          it 'accepts options' do
            icmp = ICMPv6.new(type: 255, code: 254, sum: 0x1234, body: 'abcd')
            expect(icmp.type).to eq(255)
            expect(icmp.code).to eq(254)
            expect(icmp.sum).to eq(0x1234)
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
            expect(icmp.sum).to eq(0xb867)
            expected = "\0\0\0\0\x2a\x01\x0e\x35\x8b\x7f\x9c\x10\x12\x8b" \
                       "\x3c\x32\xc3\xe4\xc0\x1b\x01\x01\x68\xa3\x78\x03" \
                       "\xcc\xb2"
            expect(icmp.body).to eq(PacketGen.force_binary expected)
          end

          it 'raises when str is too short' do
            expect { icmp.read 'aa' }.to raise_error(ParseError, /too short/)
            expect { icmp.read('aaa') }.to raise_error(ParseError, /too short/)
          end
        end

        describe '#calc_sum' do
          it 'computes ICMPv6 header checksum' do
            packets = Packet.read(pcapng_file)
            packets.each do |pkt|
              sum = pkt.icmpv6.sum
              pkt.icmpv6.sum = 0
              expect(pkt.icmpv6.sum).to_not eq(sum)
              pkt.calc
              expect(pkt.icmpv6.sum).to eq(sum)
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

          it '#sum= accepts integers' do
            icmp.sum = 0xffff
            expect(icmp[:sum].to_i).to eq(65535)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            str = PcapNG::File.new.read_packet_bytes(pcapng_file).first
            icmp = Packet.parse(str)
            expect(icmp.to_s).to eq(str)
          end
        end
      end
    end
  end
end
