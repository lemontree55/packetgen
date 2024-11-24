# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module PcapNG
    describe SHB do
      before { @shb = SHB.new }

      it 'has correct initialization values' do
        expect(@shb).to be_a(SHB)
        expect(@shb.endian).to eq(:little)
        expect(@shb.type).to eq(PcapNG::SHB_TYPE.to_i)
        expect(@shb.block_len).to eq(SHB::MIN_SIZE)
        expect(@shb[:magic].to_s).to eq(SHB::MAGIC_LITTLE)
        expect(@shb.ver_major).to eq(1)
        expect(@shb.ver_minor).to eq(0)
        expect(@shb.section_len).to eq(0xffffffff_ffffffff)
        expect(@shb.block_len2).to eq(@shb.block_len)
        expect(@shb.interfaces).to eq([])
        expect(@shb.unknown_blocks).to eq([])
      end

      context 'when reading' do
        it 'accepts a String' do
          str = ::File.read(::File.join(__dir__, 'sample.pcapng'), 52)
          expect { @shb.read(str) }.not_to raise_error
          expect(@shb.block_len).to eq(52)
          expect(@shb.options?).to be(true)
        end

        it 'accepts an IO' do
          ::File.open(::File.join(__dir__, 'sample.pcapng')) do |f|
            @shb.read(f)
          end
          expect(@shb.block_len).to eq(52)
          expect(@shb.options?).to be(true)
        end
      end
    end
  end
end
