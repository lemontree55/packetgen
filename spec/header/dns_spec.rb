require_relative '../spec_helper'

module PacketGen
  module Header

    describe DNS do
      let(:dns_pcapng) { 'dns.pcapng' }

      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(DNS).with(sport: 53)
          expect(UDP).to know_header(DNS).with(dport: 53)
          expect(TCP).to know_header(DNS).with(sport: 53)
          expect(TCP).to know_header(DNS).with(dport: 53)
        end
      end

      describe '#initialize' do
        it 'creates a DNS header with default values' do
          dns = DNS.new
          expect(dns.id).to eq(0)
          expect(dns.qr?).to be(false)
          expect(dns.aa?).to be(false)
          expect(dns.tc?).to be(false)
          expect(dns.rd?).to be(false)
          expect(dns.ra?).to be(false)
          expect(dns.aa?).to be(false)
          expect(dns.cd?).to be(false)
          expect(dns.opcode).to eq(0)
          expect(dns.rcode).to eq(0)
          expect(dns.qdcount).to eq(0)
          expect(dns.ancount).to eq(0)
          expect(dns.nscount).to eq(0)
          expect(dns.arcount).to eq(0)
          expect(dns.qd).to be_empty
          expect(dns.an).to be_empty
          expect(dns.ns).to be_empty
          expect(dns.ar).to be_empty
        end

        it 'accepts options' do
          options = {
            id: 0x1234,
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
            qr: true,
            aa: false,
            tc: true,
            rd: true,
            ra: true,
            opcode: 0xe,
            rcode: 0x9
          }
          dns = DNS.new(options)

          options.each do |key, value|
            meth = key.to_s
            meth << '?' if value.is_a?(TrueClass) or value.is_a?(FalseClass)
            expect(dns.send(meth.to_sym)).to eq(value)
          end
        end
     end

      describe '#read' do
        let(:dns) { DNS.new}

        it 'sets header from a string' do
          str = (0...dns.sz).to_a.pack('C*')
          dns.read str
          expect(dns.id).to eq(0x0001)
          expect(dns.qr? || dns.aa? || dns.rd? || dns.ra?).to be(false)
          expect(dns.tc?).to be(true)
          expect(dns.opcode).to eq(0)
          expect(dns.rcode).to eq(3)
          expect(dns.qdcount).to eq(0x0405)
          expect(dns.ancount).to eq(0x0607)
          expect(dns.nscount).to eq(0x0809)
          expect(dns.arcount).to eq(0x0a0b)
        end

        it 'also sets others sections from a string' do
          str = read_raw_packets(dns_pcapng).last
          dns.read str[0x3e..-1]
          expect(dns.id).to eq(0xd10)
          expect(dns.u16.to_i).to be(0x8180)
          expect(dns.response?).to be(true)
          expect(dns.query?).to be(false)
          expect(dns.aa?).to be(false)
          expect(dns.tc?).to be(false)
          expect(dns.rd?).to be(true)
          expect(dns.ra?).to be(true)
          expect(dns.z?).to be(false)
          expect(dns.ad?).to be(false)
          expect(dns.cd?).to be(false)
          expect(dns.opcode).to eq(0)
          expect(dns.rcode).to eq(0)
          expect(dns.qdcount).to eq(1)
          expect(dns.qd.size).to eq(1)
          expect(dns.ancount).to eq(2)
          expect(dns.an.size).to eq(2)
          expect(dns.nscount).to eq(0)
          expect(dns.ns.size).to eq(0)
          expect(dns.arcount).to eq(1)
          expect(dns.ar.size).to eq(1)

          expect(dns.qd.to_human).to eq('* IN www.google.com.')
          expect(dns.an.to_human).to eq('A IN www.google.com. TTL 189 216.58.212.132,' \
                                        'AAAA IN www.google.com. TTL 204 ' \
                                        '2a00:1450:400e:800::2004')
          expect(dns.ar.to_human).to eq('. OPT UDPsize:4096 extRCODE:0 ' \
                                        'EDNSversion:0 flags:none options:none')
        end
      end

      describe 'setters' do
        let(:dns) { DNS.new}

        it '#id= accepts integers' do
          dns.id = 0x8000
          expect(dns[:id].value).to eq(0x8000)
        end

        it '#qdcount= accepts integers' do
          dns.qdcount = 0x8000
          expect(dns[:qdcount].value).to eq(0x8000)
        end

        it '#ancount= accepts integers' do
          dns.ancount = 0x8000
          expect(dns[:ancount].value).to eq(0x8000)
        end

        it '#nscount= accepts integers' do
          dns.nscount = 0x8000
          expect(dns[:nscount].value).to eq(0x8000)
        end

        it '#arcount= accepts integers' do
          dns.arcount = 0x8000
          expect(dns[:arcount].value).to eq(0x8000)
        end

        it '#opcode= accepts integers' do
          dns.opcode = 1
          expect((dns[:u16].value & 0x7800) >> 11).to eq(1)
        end

        it '#opcode= accepts known string opcodes' do
          DNS::OPCODES.each do |opcode, num|
            dns.opcode = opcode
            expect(dns.opcode).to eq(num)
          end
        end

        it '#opcodes raises on unknown opcode' do
          expect { dns.opcode = 'blah' }.to raise_error(ArgumentError)
        end

        it '#rcode= accepts integers' do
          dns.rcode = 8
          expect(dns[:u16].value & 0xf).to eq(8)
        end

        it '#rcode= accepts known string opcodes' do
          DNS::RCODES.each do |rcode, num|
            dns.rcode = rcode
            expect(dns.rcode).to eq(num)
          end
        end

        it '#rcodes raises on unknown rcode' do
          expect { dns.rcode = 'blah' }.to raise_error(ArgumentError)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          strings = read_raw_packets(dns_pcapng)
          strings.each do |str|
            pkt = Packet.parse(str)
            expect(pkt.is? 'DNS').to be(true)
            expect(pkt.to_s).to eq(str)
          end
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          dns = DNS.new
          str = dns.inspect
          expect(str).to be_a(String)
          (dns.fields - %i(u16) + %i(flags opcode rcode)).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      context 'sections' do
        let(:dns) { DNS.new }

        it 'may add a Question to question section' do
          q = DNS::Question.new(dns, name: 'www.example.org')
          expect { dns.qd << q }.to change { dns.qdcount }.by(1)
          expected_str = "\x00" * 5 + "\x01" + "\x00" * 6 +
                         generate_label_str(%w(www example org)) +
                         "\x00\x01\x00\x01"
          expect(dns.to_s).to eq(PacketGen.force_binary expected_str)
        end

        it 'may add a RR to answer section' do
          an = DNS::RR.new(dns, name: 'www.example.org', type: 'AAAA', ttl: 3600,
                           rdata: IPAddr.new('2000::1').hton)
          expect { dns.an << an }.to change { dns.ancount }.by(1)
          expected_str = "\x00" * 7 + "\x01" + "\x00" * 4 +
                         generate_label_str(%w(www example org)) +
                         "\x00\x1c\x00\x01\x00\x00\x0e\x10\x00\x10\x20" +
                         "\x00" * 14 + "\x01"
          expect(dns.to_s).to eq(PacketGen.force_binary expected_str)
        end
      end
    end
  end
end
