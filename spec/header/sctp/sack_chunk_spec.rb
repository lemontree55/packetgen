require_relative '../../spec_helper'

module PacketGen
  module Header
    class SCTP
      describe SackChunk do
        describe '#initialize' do
          it 'creates an SackChunk header with default values' do
            data = SackChunk.new
            expect(data).to be_a(SackChunk)
            expect(data.type).to eq(3)
            expect(data.flags).to eq(0)
            expect(data.length).to eq(0)
            expect(data.ctsn_ack).to eq(0)
            expect(data.a_rwnd).to eq(0)
            expect(data.num_gap).to eq(0)
            expect(data.num_dup_tsn).to eq(0)
            expect(data.gaps.size).to eq(0)
            expect(data.dup_tsns.size).to eq(0)
          end

          it 'accepts options' do
            options = {
                      type: 0x1234,
                      flags: 0x5678,
                      length: 42,
                      ctsn_ack: 0x01020304,
                      a_rwnd: 0x05060708,
                      num_gap: 2,
                      num_dup_tsn: 1,
                      gaps: [0x000010002, 0x00100020],
                      dup_tsns: [0x12345678]
                      }
            data = SackChunk.new(options)
            options.each do |key, value|
              val = data.send(key)
              val = val.map(&:to_human) if val.is_a?(Types::Array)
              expect(val).to eq(value)
            end
          end
        end
      end
    end
  end
end
