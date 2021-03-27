require_relative '../spec_helper'

module PacketGen
  module Header
    describe GRE do
      describe 'binding' do
        it 'in IP packets' do
          expect(IP).to know_header(GRE).with(protocol: 47)
        end
        it 'accepts to be added in IP packets' do
          pkt = PacketGen.gen('IP')
          expect { pkt.add('GRE') }.to_not raise_error
          expect(pkt.ip.protocol).to eq(47)
        end

        it 'in IPv6 packets' do
          expect(IPv6).to know_header(GRE).with(next: 47)
        end
        it 'accepts to be added in IPv6 packets' do
          pkt = PacketGen.gen('IPv6')
          expect { pkt.add('GRE') }.to_not raise_error
          expect(pkt.ipv6.next).to eq(47)
        end

        it 'of IP packets' do
          expect(GRE).to know_header(IP).with(protocol_type: 0x800)
        end
        it 'accepts IP headers to be added' do
          pkt = PacketGen.gen('GRE')
          expect { pkt.add('IP') }.to_not raise_error
          expect(pkt.gre.protocol_type).to eq(0x800)
        end

        it 'of IPv6 packets' do
          expect(GRE).to know_header(IPv6).with(protocol_type: 0x86dd)
        end
        it 'accepts IPv6 headers to be added' do
          pkt = PacketGen.gen('GRE')
          expect { pkt.add('IPv6') }.to_not raise_error
          expect(pkt.gre.protocol_type).to eq(0x86dd)
        end
      end

      describe '#initialize' do
        it 'creates a GRE header with default values' do
          gre = GRE.new
          expect(gre.c?).to be(false)
          expect(gre.k?).to be(false)
          expect(gre.s?).to be(false)
          expect(gre.reserved0).to eq(0)
          expect(gre.checksum).to eq(0)
          expect(gre.reserved1).to eq(0)
        end

        it 'accepts options' do
          options = {
            c: true,
            checksum: 0x1234,
            protocol_type: 0x5678
          }
          gre = GRE.new(options)

          options.each do |key, value|
            meth = key.to_s
            meth << '?' if value.is_a?(TrueClass) or value.is_a?(FalseClass)
            expect(gre.send(meth)).to eq(value)
          end
        end

        describe '#read' do
          let(:gre) { GRE.new }

          it 'sets header from a string' do
            str = binary("\xff" + (0..14).to_a.pack('C*')) + 'body'
            gre.read str
            expect(gre.c?).to be(true)
            expect(gre.k?).to be(true)
            expect(gre.s?).to be(true)
            expect(gre.u16).to eq(0xff00)
            expect(gre.protocol_type).to eq(0x102)
            expect(gre.checksum).to eq(0x304)
            expect(gre.reserved1).to eq(0x506)
            expect(gre.key).to eq(0x708090a)
            expect(gre.seqnum).to eq(0xb0c0d0e)
          end

          it 'does not set not-present optional fields' do
            str = binary("\xa0" + (1..15).to_a.pack('C*')) + 'body'
            gre.read str
            expect(gre.c?).to be(true)
            expect(gre.k?).to be(true)
            expect(gre.s?).to be(false)
            expect(gre.ver).to eq(1)
            expect(gre.u16).to eq(0xa001)
            expect(gre.protocol_type).to eq(0x203)
            expect(gre.checksum).to eq(0x405)
            expect(gre.reserved1).to eq(0x607)
            expect(gre.key).to eq(0x8090a0b)
            expect(gre.seqnum).to eq(0)
            expect(gre.present?(:checksum)).to be(true)
            expect(gre.present?(:key)).to be(true)
            expect(gre.present?(:sequence_number)).to be(false)
          end

          it 'parses a complete GRE packet' do
            pkt = Packet.read(File.join(__dir__, 'gre.pcapng')).first
            expect(pkt.is? 'IP').to be(true)
            expect(pkt.is? 'GRE').to be(true)
            expect(pkt.is? 'ICMP').to be(true)
            expect(pkt.ip(1)).to be_a(Header::IP)
            expect(pkt.ip(1).body).to be_a(Header::GRE)
            expect(pkt.ip(2)).to be_a(Header::IP)
            expect(pkt.ip(2).body).to be_a(Header::ICMP)
          end
        end

        describe '#calc_checksum' do
          it 'computes GRE checksum' do
            pkt = Packet.read(File.join(__dir__, 'gre.pcapng')).first
            pkt.gre.checksum = 0
            pkt.gre.calc_checksum
            expect(pkt.gre.checksum).to eq(0x77ff)
          end
        end

        describe '#to_s' do
          let(:gre) { GRE.new}

          it 'returns a binary string' do
            gre.u16 = 0xb000
            gre.protocol_type = IP::ETHERTYPE
            gre.checksum = 0xcafe
            gre.key = 0xacacacac
            gre.seqnum = 0x53535353
            gre.body = 'body'
            expected_str = binary("\xb0\x00\x08\x00\xca\xfe\x00\x00" \
                                                  "\xac\xac\xac\xac\x53\x53\x53\x53" \
                                                  'body')
            expect(gre.to_s).to eq(expected_str)
          end

          it 'returns a binary string without absent optional fields' do
            gre.u16 = 0x3000
            gre.protocol_type = IP::ETHERTYPE
            gre.key = 0xacacacac
            gre.seqnum = 0x53535353
            gre.body = 'body'
            expected_str = binary("\x30\x00\x08\x00" \
                                                  "\xac\xac\xac\xac\x53\x53\x53\x53" \
                                                  'body')
            expect(gre.to_s).to eq(expected_str)
          end
        end

        describe '#inspect' do
          let(:gre) { GRE.new}

          it 'returns a String with all attributes' do
            gre.u16 = 0xb000
            str = gre.inspect
            expect(str).to be_a(String)
            (gre.fields - %i(body)).each do |attr|
              expect(str).to include(attr.to_s)
            end
          end

          it 'returns a String without not-present attributes' do
            gre.u16 = 0x8000
            str = gre.inspect
            expect(str).to be_a(String)
            fields = gre.fields - %i[body]
            fields -= gre.optional_fields.reject { |f| gre.present?(f) }
            fields.each do |attr|
              expect(str).to include(attr.to_s)
            end
            gre.optional_fields.reject { |f| gre.present?(f) }.each do |attr|
              expect(str).to_not include(attr.to_s)
            end
          end
        end
      end
    end
  end
end
