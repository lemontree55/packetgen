require_relative '../../spec_helper'

module PacketGen
  module Header
    class DNS

      describe RR do
        let(:dns) { DNS.new }

        describe '#initialize' do
          it 'creates a RR with default values' do
            rr = RR.new(dns)
            expect(rr.name.to_s).to eq('.')
            expect(rr.type).to eq(1)
            expect(rr.rrclass).to eq(1)
            expect(rr.ttl).to eq(0)
            expect(rr.rdlength).to eq(0)
            expect(rr.rdata).to eq('')
          end

          it 'accepts options' do
            options = {
              name: 'www.example.net.',
              type: 48,
              rrclass: 2,
              ttl: 0xffff_8765,
              rdlength: 0xf000,
              rdata: 'azertyuiop'
            }
            rr = RR.new(dns, options)

            expect(rr.name).to eq(options.delete :name)
            options.each do |key, value|
              expect(rr.send(key)).to eq(value)
            end
          end
        end

        describe '#read' do
          it 'sets RR from a string' do
            str = [0, 2, 3].pack('Cnn')
            rr = RR.new(dns).read(str)
            expect(rr.name).to eq('.')
            expect(rr.type).to eq(2)
            expect(rr.rrclass).to eq(3)

            str = generate_label_str(%w(example org))
            str << [1, 1, 0x3_0000, 4, 192, 168, 1, 1].pack('nnNnC4')
            rr.read(str)
            expect(rr.name).to eq('example.org.')
            expect(rr.type).to eq(1)
            expect(rr.rrclass).to eq(1)
            expect(rr.ttl).to eq(0x3_0000)
            expect(rr.rdlength).to eq(4)
            expect(rr.rdata).to eq(IPAddr.new('192.168.1.1').hton)
          end
        end

        describe 'setters' do
          let(:rr) { RR.new(dns) }

          it '#ttl= accepts an Integer' do
            rr.ttl = 0xcafe_deca
            expect(rr[:ttl].to_i).to eq(0xcafe_deca)
          end

          it '#rdlength= accepts an Integer' do
            rr.rdlength = 0xcafe
            expect(rr[:rdlength].to_i).to eq(0xcafe)
          end

          it '#rrclass= raises an error when string is unknown' do
            expect { rr.rrclass = 'blah' }.to raise_error(ArgumentError, /unknown class/)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            rr = RR.new(dns, name: 'example.net')
            expected_str = generate_label_str(%w(example net))
            expected_str << [1, 1, 0, 0].pack('nnNn')
            expect(rr.to_s).to eq(PacketGen.force_binary expected_str)
          end
        end

        describe '#human_rdata' do
          let(:rr) { RR.new(dns) }

          it 'handles IN/A records' do
            ip = '102.47.58.29'
            rr.rdata = IPAddr.new(ip).hton
            expect(rr.human_rdata).to eq(ip)
          end

          it 'handles IN/AAAA records' do
            ip = '2a00:1234:5678:143:ff00::5e'
            rr.type = 'AAAA'
            rr.rdata = IPAddr.new(ip).hton
            expect(rr.human_rdata).to eq(ip)
          end

          it 'returns quotted binary string for others records' do
            data = File.read('/dev/random', 25)
            rr.rrclass = 'CH'
            rr.rdata = data
            expect(rr.human_rdata).to eq(data.inspect)
          end
        end

        describe '#to_human' do
          it 'returns a human readable string (IN class, A type)' do
            ipaddr = '10.0.0.1'
            rr = RR.new(dns, name: 'example.net', rdata: IPAddr.new(ipaddr).hton)
            expect(rr.to_human).to eq("A IN example.net. TTL 0 #{ipaddr}")
          end

          it 'returns a human readable string (IN class, AAAA type)' do
            ip6addr = '2a00:1:2:3:4::12e'
            rr = RR.new(dns, name: 'example.net', type: 'AAAA',
                        ttl: 3600, rdata: IPAddr.new(ip6addr).hton)
            expect(rr.to_human).to eq("AAAA IN example.net. TTL 3600 #{ip6addr}")
          end

          %w(PTR NS CNAME).each do |type|
            it "returns a human readable string (#{type} type)" do
              rr = RR.new(dns, name: 'example.net', type: type, rrclass: 3,
                          ttl: 0x10000, rdata: generate_label_str([]))
              expect(rr.to_human).to eq("#{type} CH example.net. TTL 65536 .")
            end
          end

          it 'returns a human readable string (MX type)' do
            rr = RR.new(dns, name: 'example.net', type: 'MX', rrclass: 4,
                        rdata: "\x00\x20" + generate_label_str(%w(mail example net)))
            expect(rr.to_human).to eq('MX HS example.net. TTL 0 32 mail.example.net.')
          end

          it 'returns a human readable string (SOA type)' do
            rdata = generate_label_str(%w(dns example net))
            rdata << generate_label_str(%w(mailbox example.net))
            rdata << [0xf_0000, 15000, 14999, 14998, 13210].pack('N*')
            rr = RR.new(dns, name: 'example.net', type: 6, rrclass: 3,
                        rdata: rdata)

            expected_str = 'SOA CH example.net. TTL 0 dns.example.net. ' \
                           'mailbox.example.net. 983040 15000 14999 14998 13210'
            expect(rr.to_human).to eq(expected_str)
          end
        end
      end
    end
  end
end
