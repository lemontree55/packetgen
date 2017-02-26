require_relative '../spec_helper'

module PacketGen
  module Types
    describe String do

      it '#initialize accepts a option hash' do
        expect { String.new('', length_from: nil) }.to_not raise_error
      end

      context '#read' do
        it 'reads all given string when no length_from option was given' do
          str = String.new
          read_str = (0..15).to_a.pack('C*')
          str.read read_str
          expect(str.sz).to eq(16)
          expect(str).to eq(read_str)
        end

        it 'reads only start of given string when length_from option was given' do
          len = Int8.new(6)
          str = String.new('', length_from: len)
          read_str = (0..15).to_a.pack('C*')
          str.read read_str
          expect(str.sz).to eq(6)
          expect(str).to eq(read_str[0..5])

          len.value = 12
          str.read read_str
          expect(str.sz).to eq(12)
          expect(str).to eq(read_str[0..11])
        end
      end
    end
  end
end
