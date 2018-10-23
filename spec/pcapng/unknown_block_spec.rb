require_relative '../spec_helper'

module PacketGen
  module PcapNG
    describe UnknownBlock do
      before(:each) { @ub = UnknownBlock.new }

      it 'should have correct initialization values' do
        expect(@ub).to be_a(UnknownBlock)
        expect(@ub.endian).to eq(:little)
        expect(@ub.type).to eq(0)
        expect(@ub.block_len).to eq(UnknownBlock::MIN_SIZE)
        expect(@ub.block_len2).to eq(@ub.block_len)
        expect(@ub.options?).to be(false)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = "\xff\xff\xff\xff\x0c\x00\x00\x00\x0c\x00\x00\x00"
          expect { @ub.read(str) }.to_not raise_error
          expect(@ub.type).to eq(0xffffffff)
          expect(@ub.block_len).to eq(12)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, 'sample.pcapng')) do |f|
            @ub.read(f)
          end
          expect(@ub.type).to eq(0x0a0d0d0a)
          expect(@ub.block_len).to eq(52)
        end
      end

      describe '#to_s' do
        it 'should pad body field' do
          @ub.type = 42
          @ub.body = '123'

          str = "\x2a\x00\x00\x00\x10\x00\x00\x00123\x00\x10\x00\x00\x00"
          expect(@ub.to_s).to eq(force_binary(str))
        end
      end
    end
  end
end
