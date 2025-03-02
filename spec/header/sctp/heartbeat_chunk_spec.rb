# frozen_string_literal: true

require_relative '../../spec_helper'

module PacketGen
  module Header
    class SCTP
      describe HeartbeatChunk do
        describe '#initialize' do
          it 'creates an HeartbeatChunk header with default values' do
            data = HeartbeatChunk.new
            expect(data).to be_a(HeartbeatChunk)
            expect(data.type).to eq(4)
            expect(data.info.type).to eq(1)
            expect(data.info.length).to eq(4)
            expect(data.info.value).to eq('')
          end

          it 'accepts options' do
            options = {
              type: 0x1234,
              flags: 0xaa,
              length: 42,
              info: HearbeatInfo.new(value: 'abcd')
            }
            data = HeartbeatChunk.new(options)
            options.each do |key, value|
              expect(data.send(key)).to eq(value)
            end
          end
        end
      end
    end
  end
end
