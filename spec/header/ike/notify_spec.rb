require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe Notify do
        describe '#initialize' do
          it 'creates a Notify payload with default values' do
            notify = Notify.new
            expect(notify.next).to eq(0)
            expect(notify.flags).to eq(0)
            expect(notify.length).to eq(8)
            expect(notify.protocol).to eq(0)
            expect(notify.spi_size).to eq(0)
            expect(notify.type).to eq(0)
            expect(notify.spi).to be_empty
            expect(notify.content).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              protocol: 43,
              spi_size: 55,
              message_type: 0x8765,
              spi: "\x00\x01",
              content: 'abcdefghij'
            }

            notify = Notify.new(opts)
            opts.each do |k,v|
              expect(notify.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets Notify from a binary string' do
            str = [12, 0x80, 18, 1, 4, 0x100, 0x12345678, 'abcdef'].pack('CCnCCnNA*')
            notify = Notify.new.read(str)
            expect(notify.next).to eq(12)
            expect(notify.flags).to eq(0x80)
            expect(notify.critical?).to be(true)
            expect(notify.hreserved).to eq(0)
            expect(notify.length).to eq(18)
            expect(notify.protocol).to eq(1)
            expect(notify.spi_size).to eq(4)
            expect(notify.type).to eq(0x100)
            expect(notify.spi).to eq([0x12345678].pack('N'))
            expect(notify.content).to eq('abcdef')
          end
        end

        describe '#protocol=' do
          let(:notify)  { Notify.new }

          it 'accepts Integer' do
            expect { notify.protocol = 43 }.to_not raise_error
            expect(notify.protocol).to eq(43)
            expect(notify.human_protocol).to eq('proto 43')
          end

          it 'accepts String' do
            expect { notify.protocol = 'ESP' }.to_not raise_error
            expect(notify.protocol).to eq(IKE::PROTO_ESP)
            expect(notify.human_protocol).to eq('ESP')
          end

          it 'raises on unknown type (String only)' do
            expect { notify.protocol = 'TCP' }.to raise_error(ArgumentError)
          end
        end

        describe '#message_type=' do
          let(:notify)  { Notify.new }

          it 'accepts Integer' do
            expect { notify.message_type = 59 }.to_not raise_error
            expect(notify.message_type).to eq(59)
            expect(notify.human_type).to eq('type 59')
          end

          it 'accepts String' do
            expect { notify.message_type = 'AUTHENTICATION_FAILED' }.to_not raise_error
            expect(notify.message_type).to eq(Notify::TYPE_AUTHENTICATION_FAILED)
            expect(notify.human_type).to eq('AUTHENTICATION_FAILED')
          end

          it 'raises on unknown type (String only)' do
            expect { notify.message_type = 'READ_ERROR' }.to raise_error(ArgumentError)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            notify = Notify.new(next: 2, protocol: 'AH', type: 'COOKIE',
                                spi: 'yz', content: 'abcdefghijkl')
            notify.calc_length
            expected = "\x02\x00\x00\x16\x02\x02\x40\x06yzabcdefghijkl"
            expect(notify.to_s).to eq(PacketGen.force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            notify = Notify.new
            str = notify.inspect
            expect(str).to be_a(String)
            (notify.fields - %i(body)).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end
      end
    end
  end
end
