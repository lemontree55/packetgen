require_relative '../spec_helper'

module PacketGen
  module Types
    describe TLV do

      context '#initialize' do
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
      end

      context '#read' do
        it 'reads a TLV from a binary string' do
          bin_str = [1, 2, 0x12345678].pack('CCN')
          tlv = TLV.new.read(bin_str)
          expect(tlv.type).to eq(1)
          expect(tlv.length).to eq(2)
          expect(tlv.value).to eq(PacketGen.force_binary "\x12\x34")

          bin_str = [1, 3, 0x12345678].pack('nnN')
          tlv = TLV.new(l: Int16, t: Int16).read(bin_str)
          expect(tlv.type).to eq(1)
          expect(tlv.length).to eq(3)
          expect(tlv.value).to eq(PacketGen.force_binary "\x12\x34\x56")
        end
      end
    end
  end
end
