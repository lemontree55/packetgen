require_relative '../../spec_helper'

INIT_CHUNK_WITH_PARAMS = '<chunk:INIT,param:<IPv4: 92.168.52.17>,<IPv6: 2c00:5d3::42>,<StateCookie: "cookie">,<Unrecognized: <type:<unknown:42>,length:7,value:"abc">,<Hostname: www.example.com>,<SupportedAddrTypes: IPv4,IPv6>,<CookiePreservative: 1545>,<ECN>>'

module PacketGen
  module Header
    class SCTP
      describe InitChunk do
        describe '#initialize' do
          it 'creates an InitChunk header with default values' do
            init = InitChunk.new
            expect(init).to be_a(InitChunk)
            expect(init.type).to eq(1)
            expect(init.flags).to eq(0)
            expect(init.length).to eq(0)
            expect(init.initiate_tag).to eq(0)
            expect(init.a_rwnd).to eq(0)
            expect(init.nos).to eq(0)
            expect(init.nis).to eq(0)
            expect(init.initial_tsn).to eq(0)
            expect(init.parameters.size).to eq(0)
          end

          it 'accepts options' do
            options = {
                      type: 0xffff,
                      flags: 0x1234,
                      length: 42,
                      initiate_tag: 0x01020304,
                      a_rwnd: 0x05060708,
                      nos: 0x8000,
                      nis: 0xf00E,
                      initial_tsn: 0x090a0b0c,
                      }
            init = InitChunk.new(options)
            options.each do |key, value|
              expect(init.send(key)).to eq(value)
            end
          end
        end

        describe '#to_human' do
          it 'returns a String with type' do
            expect(InitChunk.new.to_human).to eq('<chunk:INIT>')
          end

          it 'returns human readable parameters' do
            init = InitChunk.new
            init.parameters << { type: 'IPv4', value: '92.168.52.17' }
            init.parameters << { type: 'IPv6', value: '2c00:5d3::42' }
            init.parameters << { type: 'StateCookie', value: "cookie" }
            init.parameters << { type: 'Unrecognized', value: Parameter.new(type: 42, value: 'abc') }
            init.parameters << { type: 'Hostname', value: 'www.example.com' }
            init.parameters << { type: 'SupportedAddrTypes', value: [5, 6]}
            init.parameters << { type: 'CookiePreservative', value: 1_545 }
            init.parameters << { type: 'ECN' }

            output = init.to_human
            expect(output).to eq(INIT_CHUNK_WITH_PARAMS)
          end
        end

        describe '#parameters' do
          let(:init) { InitChunk.new }
          let(:param1) { Parameter.new(type: 42, value: 'AAAA') }
          let(:param2) { IPv4Parameter.new(type: 'IPv4', value: '10.0.0.1') }
          it 'accepts Parameter using <<' do
            init.parameters << param1
            init.parameters << param2
            expect(init.parameters.size).to eq(2)
            expect(init.parameters[0]).to eq(param1)
            expect(init.parameters[1]).to eq(param2)
          end

          it 'accepts Hash describing a Parameter using <<' do
            init.parameters << { type: 42, value: 'AAAA'}
            init.parameters << { type: 5, value: '10.0.0.1'}
            init.parameters << { type: 'IPv4', value: '10.0.0.1'}
            expect(init.parameters.size).to eq(3)
            expect(init.parameters[0]).to be_a(Parameter)
            expect(init.parameters[0].to_s).to eq(param1.to_s)
            expect(init.parameters[1]).to be_a(IPv4Parameter)
            expect(init.parameters[1].to_s).to eq(param2.to_s)
            expect(init.parameters[2]).to be_a(IPv4Parameter)
            expect(init.parameters[2].to_s).to eq(param2.to_s)
          end
        end

        describe '#to_s' do
          let(:init) { InitChunk.new(initiate_tag: 0xfffefdfc, nos: 1, nis: 2) }

          it 'converts a simple InitChunk to String' do
            bin = binary("\x01\x00\x00\x00\xff\xfe\xfd\xfc\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00")
            expect(init.to_s).to eq(bin)
          end

          it 'converts an InitChunk with parameters to String' do
            init.parameters << { type: 'ECN' }
            init.parameters << { type: 'IPv4', value: '1.2.3.4' }
            init.calc_length

            bin = binary("\x01\x00\x00\x20\xff\xfe\xfd\xfc\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00")
            bin << binary("\x80\x00\x00\x04")
            bin << binary("\x00\x05\x00\x08\x01\x02\x03\x04")
            expect(init.to_s).to eq(bin)
          end
        end
      end
    end
  end
end
