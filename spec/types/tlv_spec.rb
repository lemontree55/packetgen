require_relative '../spec_helper'

module PacketGen
  module Types
    describe TLV do

      class TLVTest < TLV
        TYPES = { 1 => 'one', 2 => 'two' }
      end

      describe '#initialize' do
        it 'returns a TLV with default values' do
          tlv = TLV.new
          expect(tlv[:type]).to be_a(Int8)
          expect(tlv[:length]).to be_a(Int8)
          expect(tlv[:value]).to be_a(String)
        end

        it 'builds a TLV with others sizes for T and L' do
          tlv = TLV.new(t: Int16)
          expect(tlv[:type]).to be_a(Int16)
          expect(tlv[:length]).to be_a(Int8)
          expect(tlv[:value]).to be_a(String)

          tlv = TLV.new(l: Int16)
          expect(tlv[:type]).to be_a(Int8)
          expect(tlv[:length]).to be_a(Int16)
          expect(tlv[:value]).to be_a(String)
        end

        it 'accepts field options' do
          tlv = TLV.new(type: 45, value: 'abc', length: 2)
          expect(tlv.type).to eq(45)
          expect(tlv.length).to eq(2)
          expect(tlv.value).to eq('abc')
        end
      end

      describe '#read' do
        it 'reads a TLV from a binary string' do
          bin_str = [1, 2, 0x12345678].pack('CCN')
          tlv = TLV.new.read(bin_str)
          expect(tlv.type).to eq(1)
          expect(tlv.length).to eq(2)
          expect(tlv.value).to eq(force_binary "\x12\x34")

          bin_str = [1, 3, 0x12345678].pack('nnN')
          tlv = TLV.new(l: Int16, t: Int16).read(bin_str)
          expect(tlv.type).to eq(1)
          expect(tlv.length).to eq(3)
          expect(tlv.value).to eq(force_binary "\x12\x34\x56")
        end
      end

      describe '#type=' do
        it 'raises when setting a String and there is no TYPES constant' do
          expect { TLV.new.type = 'TRUC' }.to raise_error(TypeError, 'need an Integer')
        end

        it 'accepts a String if subclass defines a TYPES constant' do
          tlv = TLVTest.new
          expect { tlv.type = 'two' }.to_not raise_error
          expect(tlv.type).to eq(2)
        end

        it 'raises if String is unknown from TYPES hash' do
          tlv = TLVTest.new
          expect { tlv.type = 'three' }.to raise_error(ArgumentError, /unknown/)
        end
      end

      describe '#human_type' do
        it 'returns human readable type, if TYPES is defined' do
          tlv = TLVTest.new
          tlv.type = 'one'
          expect(tlv.type).to eq(1)
          expect(tlv.human_type).to eq('one')
        end

        it 'returns integer string, if TYPES is undefined or type has no string' do
          tlv = TLVTest.new
          tlv.type = 3
          expect(tlv.type).to eq(3)
          expect(tlv.human_type).to eq('3')

          tlv = TLV.new
          tlv.type = 12
          expect(tlv.human_type).to eq('12')
        end
      end

      describe '#to_human' do
        it 'returns a string for subtypes with a TYPES constant' do
          tlv = TLVTest.new(type: 1, value: 'abcdef')
          expect(tlv.to_human).to eq('TLVTest type:one length:6   value:"abcdef"')
        end

        it 'returns a string for subtypes without a TYPES constant' do
          tlv = TLV.new
          expect(tlv.to_human).to eq('TLV type:0 length:0   value:""')
          tlv.type = 156
          tlv.value = 'abcd'
          expect(tlv.to_human).to eq('TLV type:156 length:4   value:"abcd"')
        end
      end
    end
  end
end
