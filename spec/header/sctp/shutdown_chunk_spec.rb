# frozen_string_literal: true

require_relative '../../spec_helper'

module PacketGen
  module Header
    class SCTP
      describe ShutdownChunk do
        describe '#initialize' do
          it 'creates an ShutdownChunk header with default values' do
            shutdown = ShutdownChunk.new
            expect(shutdown).to be_a(ShutdownChunk)
            expect(shutdown.type).to eq(7)
            expect(shutdown.flags).to eq(0)
            expect(shutdown.length).to eq(8)
            expect(shutdown.ctsn_ack).to eq(0)
          end

          it 'accepts options' do
            options = {
              type: 0xffff,
              flags: 0x1234,
              length: 42,
              ctsn_ack: 0x01020304,
            }
            shutdown = ShutdownChunk.new(options)
            options.each do |key, value|
              expect(shutdown.send(key)).to eq(value)
            end
          end
        end

        describe '#to_human' do
          it 'returns a String with type' do
            expect(ShutdownChunk.new.to_human).to eq('<chunk:SHUTDOWN>')
          end
        end

        describe '#to_s' do
          it 'converts to binary String' do
            shutdown = ShutdownChunk.new(ctsn_ack: 0xfffefdfc)
            bin = binary("\x07\x00\x00\x08\xff\xfe\xfd\xfc")
            expect(shutdown.to_s).to eq(bin)
          end
        end
      end

      describe ShutdownAckChunk do
        describe '#initialize' do
          it 'creates an ShutdownChunk header with default values' do
            shutdown = ShutdownAckChunk.new
            expect(shutdown).to be_a(ShutdownAckChunk)
            expect(shutdown.type).to eq(8)
            expect(shutdown.flags).to eq(0)
            expect(shutdown.length).to eq(4)
          end

          it 'accepts options' do
            options = {
              type: 0xffff,
              flags: 0x1234,
              length: 42,
            }
            shutdown = ShutdownAckChunk.new(options)
            options.each do |key, value|
              expect(shutdown.send(key)).to eq(value)
            end
          end
        end

        describe '#to_human' do
          it 'returns a String with type' do
            expect(ShutdownAckChunk.new.to_human).to eq('<chunk:SHUTDOWN_ACK>')
          end
        end

        describe '#to_s' do
          it 'converts to binary String' do
            shutdown = ShutdownAckChunk.new
            bin = binary("\x08\x00\x00\x04")
            expect(shutdown.to_s).to eq(bin)
          end
        end
      end

      describe ShutdownCompleteChunk do
        describe '#initialize' do
          it 'creates an ShutdownChunk header with default values' do
            shutdown = ShutdownCompleteChunk.new
            expect(shutdown).to be_a(ShutdownCompleteChunk)
            expect(shutdown.type).to eq(14)
            expect(shutdown.flags).to eq(0)
            expect(shutdown.length).to eq(4)
          end

          it 'accepts options' do
            options = {
              type: 0xffff,
              flags: 0x1234,
              length: 42,
            }
            shutdown = ShutdownCompleteChunk.new(options)
            options.each do |key, value|
              expect(shutdown.send(key)).to eq(value)
            end
          end
        end

        describe '#to_human' do
          it 'returns a String with type' do
            expect(ShutdownCompleteChunk.new.to_human).to eq('<chunk:SHUTDOWN_COMPLETE>')
          end
        end

        describe '#to_s' do
          it 'converts to binary String' do
            shutdown = ShutdownCompleteChunk.new
            bin = binary("\x0e\x00\x00\x04")
            expect(shutdown.to_s).to eq(bin)
          end
        end
      end
    end
  end
end
