require_relative '../../spec_helper'

module PacketGen
  module Header
    class DNS

      describe OPT do
        let(:dns) { DNS.new }

        describe '#initialize' do
          it 'creates a OPT with default values' do
            opt = OPT.new(dns)
            expect(opt.name).to eq('.')
            expect(opt.type).to eq(41)
            expect(opt.udp_size).to eq(512)
            expect(opt.ttl).to eq(0)
            expect(opt.ext_rcode).to eq(0)
            expect(opt.version).to eq(0)
            expect(opt.do?).to eq(false)
            expect(opt.rdlength).to eq(0)
            expect(opt.rdata).to eq('')
          end

          it 'accepts options' do
            options = {
              name: 'www.example.net.',
              type: 249,
              udp_size: 2048,
              ext_rcode: 0x80,
              version: 0x91,
              do: true,
              rdlength: 0xf000,
              rdata: 'azertyuiop'
            }
            opt = OPT.new(dns, options)

            expect(opt.name).to eq(options.delete :name)
            options.each do |key, value|
              meth = key.to_s
              meth << '?' if  value.is_a?(TrueClass) or value.is_a?(FalseClass)
              expect(opt.send(meth)).to eq(value)
            end
          end
        end

        describe '#read' do
          it 'sets OPT from a string' do
            str = [0, 2, 1024, 0x10, 1, 0xc1ac, 0].pack('CnnCCnn')
            opt = OPT.new(dns).read(str)
            expect(opt.name).to eq('.')
            expect(opt.type).to eq(2)
            expect(opt.udp_size).to eq(1024)
            expect(opt.ext_rcode).to eq(0x10)
            expect(opt.version).to eq(1)
            expect(opt.do?).to eq(true)
            expect(opt.z).to eq(0x41ac)
          end
        end

        describe 'setters' do
          let(:opt) { OPT.new(dns) }

          it '#udp_size= accepts an Integer' do
            opt.udp_size = 0xacac
            expect(opt[:rrclass].to_i).to eq(0xacac)
          end

          it '#ext_rcode= accepts an Integer' do
            opt.ext_rcode = 0x72
            expect(opt[:ttl].to_i).to eq(0x7200_0000)
          end

          it '#version= accepts an Integer' do
            opt.version = 0x42
            expect(opt[:ttl].to_i).to eq(0x42_0000)
          end

          it '#do= accepts an Boolean' do
            opt.do = true
            expect(opt[:ttl].to_i).to eq(0x8000)
            opt.do = false
            expect(opt[:ttl].to_i).to eq(0)
          end

          it '#rdlength= accepts an Integer' do
            opt.rdlength = 0xcafe
            expect(opt[:rdlength].to_i).to eq(0xcafe)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            opt = OPT.new(dns, name: 'example.net', udp_size: 512, version: 10)
            expected_str = [7, 'example', 3, 'net', 0, 41, 512, 0xa0000, 0].
                           pack('CA7CA3CnnNn')
            expect(opt.to_s).to eq(force_binary expected_str)
          end
        end

        describe '#to_human' do
          it 'returns a human readable string' do
            opt = OPT.new(dns, udp_size: 600, ext_rcode: 45, version: 1, do: true)
            expect(opt.to_human).to eq('. OPT UDPsize:600 extRCODE:45 EDNSversion:1' \
                                       ' flags:do options:none')
            opt = OPT.new(dns, name: 'org')
            expect(opt.to_human).to eq('org. OPT UDPsize:512 extRCODE:0 EDNSversion:0' \
                                       ' flags:none options:none')
          end
        end
      end
    end
  end
end
