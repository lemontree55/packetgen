# frozen_string_literal: true

require_relative '../../spec_helper'

module PacketGen
  module Header
    class SCTP
      describe DataChunk do
        describe '#initialize' do
          it 'creates an DataChunk header with default values' do
            data = DataChunk.new
            expect(data).to be_a(DataChunk)
            expect(data.type).to eq(0)
            expect(data.flags).to eq(0)
            expect(data.length).to eq(0)
            expect(data.tsn).to eq(0)
            expect(data.stream_id).to eq(0)
            expect(data.stream_sn).to eq(0)
            expect(data.ppid).to eq(0)
            expect(data.body.size).to eq(0)
          end

          it 'accepts options' do
            options = {
              type: 0x1234,
              flags: 0x5678,
              length: 42,
              tsn: 0x01020304,
              stream_id: 0xabcd,
              stream_sn: 0xef01,
              ppid: 0xf0e0d0c0,
            }
            data = DataChunk.new(options)
            options.each do |key, value|
              expect(data.send(key)).to eq(value)
            end
          end

          it 'accepts flag options' do
            options = {
              flag_i: true,
              flag_u: true,
              flag_b: true,
              flag_e: true
            }
            data = DataChunk.new(options)
            expect(data.flags).to eq(0xf)
            expect(data.flag_i?).to be(true)
            expect(data.flag_u?).to be(true)
            expect(data.flag_b?).to be(true)
            expect(data.flag_e?).to be(true)
          end
        end

        describe '#to_human' do
          it 'returns a String with type' do
            expect(DataChunk.new.to_human).to eq('<chunk:DATA,flags:....>')
          end

          it 'returns a String with flags' do
            expect(DataChunk.new(flags: 15).to_human).to eq('<chunk:DATA,flags:iube>')
          end
        end

        it '#to_s converts a simple DataChunk to String' do
          data = DataChunk.new(flag_i: true, tsn: 1, stream_id: 0x15a3, stream_sn: 0x51, ppid: 0x7f0025a3)
          data[:body] << 'abc'
          data.calc_length
          golden = binary("\x00\x08\x00\x13\x00\x00\x00\x01\x15\xa3\x00\x51\x7f\x00\x25\xa3abc\x00")
          expect(data.to_s).to eq(golden)
        end

        it '#calc_length calculates length using body content' do
          data = DataChunk.new
          data[:body] << 'abcdef'
          data.calc_length
          expect(data.length).to eq(22)
        end

        it '#calc_length calculates length using complex body content' do
          data = DataChunk.new
          dns = DNS.new
          data[:body] = dns
          data.calc_length
          expect(data.length).to eq(16 + dns.sz)
        end
      end
    end
  end
end
