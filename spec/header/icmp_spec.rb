require_relative '../spec_helper'

module PacketGen
  module Header

    describe ICMP do
      describe 'bindings' do
        it 'in IP packets' do
          expect(IP.known_headers[ICMP].to_h).to eq({ key: :protocol, value: 1 })
        end

        describe '#initialize' do
          it 'creates a ICMP header with default values' do
            icmp = ICMP.new
            expect(icmp).to be_a(ICMP)
            expect(icmp.type).to eq(0)
            expect(icmp.code).to eq(0)
            expect(icmp.checksum).to eq(0)
            expect(icmp.body).to eq('')
          end

          it 'accepts options' do
            icmp = ICMP.new(type: 255, code: 254, checksum: 0x1234, body: 'abcd')
            expect(icmp.type).to eq(255)
            expect(icmp.code).to eq(254)
            expect(icmp.checksum).to eq(0x1234)
            expect(icmp.body).to eq('abcd')
          end
        end

        describe '#read' do
          let(:icmp) { ICMP.new}

          it 'sets header from a string' do
            str = (1..icmp.sz).to_a.pack('C*') + 'body'
            icmp.read str
            expect(icmp.type).to eq(1)
            expect(icmp.code).to eq(2)
            expect(icmp.checksum).to eq(0x0304)
            expect(icmp.body).to eq('body')
          end

          it 'raises when str is too short' do
            expect { icmp.read 'aa' }.to raise_error(ParseError, /too short/)
            expect { icmp.read('aaa') }.to raise_error(ParseError, /too short/)
          end
        end

        describe '#calc_checksum' do
          it 'computes ICMP header checksum' do
            icmp = ICMP.new(type: 1, code: 8, body: (0..15).to_a.pack('C*'))
            icmp.calc_checksum
            expect(icmp.calc_checksum).to eq(0xc6b7)
          end
        end

        describe 'setters' do
          let(:icmp) { ICMP.new}

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
            icmp = ICMP.new(type: 1, code: 8, body: (0..15).to_a.pack('C*'))
            icmp.calc_checksum
            expect(icmp.to_s).to eq(([1, 8, 0xc6, 0xb7] + (0..15).to_a).pack('C*'))
          end
        end
      end
    end
  end
end
