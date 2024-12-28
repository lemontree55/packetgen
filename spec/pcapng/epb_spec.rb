# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module PcapNG
    describe EPB do
      before { @epb = EPB.new }

      it 'has correct initialization values' do
        expect(@epb).to be_a(EPB)
        expect(@epb.endian).to eq(:little)
        expect(@epb.type).to eq(PcapNG::EPB_TYPE.to_i)
        expect(@epb.interface_id).to eq(0)
        expect(@epb.tsh).to eq(0)
        expect(@epb.tsl).to eq(0)
        expect(@epb.cap_len).to eq(0)
        expect(@epb.orig_len).to eq(0)
        expect(@epb.block_len).to eq(EPB::MIN_SIZE)
        expect(@epb.block_len2).to eq(@epb.block_len)
      end

      context 'when reading' do
        it 'accepts a String' do
          str = ::File.read(::File.join(__dir__, 'sample.pcapng'))[84, 112]
          expect { @epb.read(str) }.not_to raise_error
          expect(@epb.type).to eq(PcapNG::EPB_TYPE.to_i)
          expect(@epb.block_len).to eq(112)
          expect(@epb.interface_id).to eq(0)
          expect(@epb.tsh).to eq(0x475ad)
          expect(@epb.tsl).to eq(0xd392be6a)
          expect(@epb.cap_len).to eq(78)
          expect(@epb.orig_len).to eq(@epb.cap_len)
          expect(@epb.options?).to be(false)
        end

        it 'accepts an IO' do
          ::File.open(::File.join(__dir__, 'sample.pcapng')) do |f|
            f.seek(84, :CUR)
            @epb.read f
          end
          expect(@epb.type).to eq(PcapNG::EPB_TYPE.to_i)
          expect(@epb.block_len).to eq(112)
          expect(@epb.interface_id).to eq(0)
          expect(@epb.tsh).to eq(0x475ad)
          expect(@epb.tsl).to eq(0xd392be6a)
          expect(@epb.cap_len).to eq(78)
          expect(@epb.orig_len).to eq(@epb.cap_len)
          expect(@epb.options?).to be(false)
        end
      end

      it 'decodes packet timestamp with default resolution' do
        ::File.open(::File.join(__dir__, 'sample.pcapng')) do |f|
          f.seek(84, :CUR)
          @epb.read f
        end

        expect(@epb.timestamp.round).to eq(Time.utc(2009, 10, 11, 19, 29, 6))
      end

      it 'decodes packet timestamp with interface resolution' do
        ::File.open(::File.join(__dir__, 'sample.pcapng')) do |f|
          f.seek(84, :CUR)
          @epb.read f
        end

        idb = IDB.new
        ::File.open(::File.join(__dir__, 'sample.pcapng')) do |f|
          f.seek(52, :CUR)
          idb.read f
        end
        idb << @epb
        @epb.interface = idb

        expect(@epb.timestamp.round).to eq(Time.utc(2009, 10, 11, 19, 29, 6))
      end

      describe '#timestamp=' do
        it 'sets timestamp from a Time object' do
          @epb.timestamp = Time.utc(2009, 10, 11, 19, 29, 6.244202r)
          expect(@epb.tsh).to eq(292_269)
          expect(@epb.tsl).to eq(3_549_609_578)
        end
      end
    end
  end
end
