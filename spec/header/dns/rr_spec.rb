require_relative '../../spec_helper'

module PacketGen
  module Header
    class DNS

      describe RR do
        let(:dns) { DNS.new }

        describe '#initialize' do
          it 'creates a RR with default values' do
            rr = RR.new(dns)
            expect(rr.name.to_s).to eq('')
            expect(rr.type).to eq(1)
            expect(rr.rrclass).to eq(1)
          end

          it 'accepts options' do
            options = {
              name: 'www.example.net.',
              type: 253,
              rrclass: 65000
            }
            rr = RR.new(dns, options)

            expect(rr.name.to_human).to eq(options.delete :name)
            options.each do |key, value|
              expect(rr.send(key)).to eq(value)
            end
          end
        end

        describe '#read' do
          it 'sets RR from a string' do
            str = [0, 2, 3].pack('Cnn')
            rr = RR.new(dns).read(str)
            expect(rr.name.to_human).to eq('.')
            expect(rr.type).to eq(2)
            expect(rr.rrclass).to eq(3)

            str = [7, 'example', 3, 'org', 0, 1, 1, 0x3_0000,
                   4, 192, 168, 1, 1].pack('CA7CA3CnnNnC4')
            rr = RR.new(dns).read(str)
            expect(rr.name.to_human).to eq('example.org.')
            expect(rr.type).to eq(1)
            expect(rr.rrclass).to eq(1)
            expect(rr.ttl).to eq(0x3_0000)
            expect(rr.rdlength).to eq(4)
            expect(rr.rdata).to eq(IPAddr.new('192.168.1.1').hton)
          end
        end

        describe 'setters' do
          let(:rr) { RR.new(dns) }

          it '#type= accepts an Integer' do
            rr.type = 0xacac
            expect(rr[:type].to_i).to eq(0xacac)
          end

          it '#type= accepts a String' do
            RR::TYPES.each do |key, value|
              rr.type = key
              expect(rr[:type].to_i).to eq(value)
            end
          end

          it '#type= raises an error when string is unknown' do
            expect { rr.type = 'blah' }.to raise_error(ArgumentError, /unknown type/)
          end

          it '#rrclass= accepts an Integer' do
            rr.rrclass = 0xacac
            expect(rr[:rrclass].to_i).to eq(0xacac)
          end

          it '#rrclass= accepts a String' do
            RR::CLASSES.each do |key, value|
              rr.rrclass = key
              expect(rr[:rrclass].to_i).to eq(value)
            end
          end

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
            expected_str = [7, 'example', 3, 'net', 0, 1, 1, 0, 0].pack('CA7CA3CnnNn')
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
          it 'returns a human readable string' do
            rr = RR.new(dns, name: 'example.net', rdata: IPAddr.new('10.0.0.1').hton)
            expect(rr.to_human).to eq('A IN example.net. TTL 0 10.0.0.1')
            rr = RR.new(dns, name: 'example.net', type: 12, rrclass: 3, ttl: 0x10000)
            expect(rr.to_human).to eq('PTR CH example.net. TTL 65536 ""')
          end
        end
      end
    end
  end
end
