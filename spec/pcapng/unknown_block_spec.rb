# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module PcapNG
    describe UnknownBlock do
      before { @ub = UnknownBlock.new }

      it 'has correct initialization values' do
        expect(@ub).to be_a(UnknownBlock)
        expect(@ub.endian).to eq(:little)
        expect(@ub.type).to eq(0)
        expect(@ub.block_len).to eq(UnknownBlock::MIN_SIZE)
        expect(@ub.block_len2).to eq(@ub.block_len)
        expect(@ub.options?).to be(false)
      end

      context 'when reading' do
        it 'accepts a String' do
          str = "\xff\xff\xff\xff\x0c\x00\x00\x00\x0c\x00\x00\x00"
          expect { @ub.read(str) }.not_to raise_error
          expect(@ub.type).to eq(0xffffffff)
          expect(@ub.block_len).to eq(12)
        end

        it 'accepts an IO' do
          ::File.open(::File.join(__dir__, 'sample.pcapng')) do |f|
            @ub.read(f)
          end
          expect(@ub.type).to eq(0x0a0d0d0a)
          expect(@ub.block_len).to eq(52)
        end
      end

      describe '#to_s' do
        it 'pads body field' do
          @ub.type = 42
          @ub.body = '123'

          str = "\x2a\x00\x00\x00\x10\x00\x00\x00123\x00\x10\x00\x00\x00".b
          expect(@ub.to_s).to eq(str)
        end
      end
    end
  end
end
