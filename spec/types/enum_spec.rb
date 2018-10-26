require_relative '../spec_helper'

ENUM_HASH = {'low' => 0, 'medium' => 1, 'high' => 2}.freeze

module PacketGen
  module Types
    describe Enum do
      let(:enum) { Enum.new(ENUM_HASH) }

      describe '#value=' do
        it 'accepts Integers in enum range' do
          3.times do |i|
            enum.value = i
            expect(enum.value).to eq(i)
          end
        end

        it 'accepts known strings' do
          ENUM_HASH.each do |key, value|
            enum.value = key
            expect(enum.value).to eq(value)
          end
        end

        it 'accepts out of range Integers' do
          expect { enum.value = 155 }.to_not raise_error
          expect(enum.to_i).to eq(155)
        end

        it 'raises on unknown strings' do
          expect { enum.value = 'azerty' }.to raise_error(ArgumentError)
        end
      end

      describe '#value' do
        it 'always returns an Integer' do
          enum.value = 2
          expect(enum.value).to be_a(Integer)
          expect(enum.value).to eq(2)
          enum.value = 'low'
          expect(enum.value).to be_a(Integer)
          expect(enum.value).to eq(0)
        end
      end

      describe '#from_human' do
        it 'accepts human redable values' do
          enum.from_human(1)
          expect(enum.to_i).to eq(1)
          enum.from_human('high')
          expect(enum.to_i).to eq(2)
        end
      end

      describe '#to_human' do
        it 'always returns a String' do
          enum.value = 2
          expect(enum.to_human).to be_a(::String)
          expect(enum.to_human).to eq('high')
          enum.value = 'low'
          expect(enum.to_human).to be_a(::String)
          expect(enum.to_human).to eq('low')
        end

        it 'returns "<unknown>" for out of range values' do
          enum.instance_eval { @value = 155 }
          expect(enum.to_human).to eq('<unknown:155>')
        end
      end
    end

    describe Int8Enum do
      let(:enum8) { Int8Enum.new(ENUM_HASH)}

      describe '#read' do
        it 'reads a single byte in enum range' do
          enum8.read("\x01")
          expect(enum8.to_human).to eq('medium')
        end

        it 'reads a single byte, even out of range' do
          enum8.read("\x7f")
          expect(enum8.to_human).to eq('<unknown:127>')
          expect(enum8.value).to eq(127)
        end
      end

      describe '#to_s' do
        it 'returns binary string from value' do
          enum8.value = 2
          expect(enum8.to_s).to eq("\x02")
          enum8.value = 'low'
          expect(enum8.to_s).to eq("\x00")
        end

        it 'returns binary string from value, even out of range' do
          enum8.read("\x7f")
          expect(enum8.to_s).to eq("\x7f")
        end
      end
    end

    [Int16Enum, Int16beEnum].each do |klass|
      describe klass do
        let(:enum16) { klass.new(ENUM_HASH)}

        describe '#read' do
          it 'reads two bytes in enum range' do
            enum16.read("\x00\x01")
            expect(enum16.to_human).to eq('medium')
          end

          it 'reads two bytes, even out of range' do
            enum16.read("\x7f\x01")
            expect(enum16.to_human).to eq('<unknown:32513>')
            expect(enum16.value).to eq(0x7f01)
          end
        end

        describe '#to_s' do
          it 'returns binary string from value' do
            enum16.value = 2
            expect(enum16.to_s).to eq("\x00\x02")
            enum16.value = 'low'
            expect(enum16.to_s).to eq("\x00\x00")
          end

          it 'returns binary string from value, even out of range' do
            enum16.read("\x01\x7f")
            expect(enum16.to_s).to eq("\x01\x7f")
          end
        end
      end
    end

    describe Int16leEnum do
      let(:enum16le) { Int16leEnum.new(ENUM_HASH)}

      describe '#read' do
        it 'reads two bytes in enum range' do
          enum16le.read("\x01\x00")
          expect(enum16le.to_human).to eq('medium')
        end

        it 'reads two bytes, even out of range' do
          enum16le.read("\x01\x7f")
          expect(enum16le.to_human).to eq('<unknown:32513>')
          expect(enum16le.value).to eq(0x7f01)
        end
      end

      describe '#to_s' do
        it 'returns binary string from value' do
          enum16le.value = 2
          expect(enum16le.to_s).to eq("\x02\x00")
          enum16le.value = 'low'
          expect(enum16le.to_s).to eq("\x00\x00")
        end

        it 'returns binary string from value, even out of range' do
          enum16le.read("\x7f\x01")
          expect(enum16le.to_s).to eq("\x7f\x01")
        end
      end
    end

    [Int32Enum, Int32beEnum].each do |klass|
      describe klass do
        let(:enum32) { klass.new(ENUM_HASH)}

        describe '#read' do
          it 'reads two bytes in enum range' do
            enum32.read(force_binary("\x00\x00\x00\x01"))
            expect(enum32.to_human).to eq('medium')
          end

          it 'reads two bytes, even out of range' do
            enum32.read(force_binary("\x7f\x00\x00\x01"))
            expect(enum32.to_human).to eq('<unknown:2130706433>')
            expect(enum32.value).to eq(0x7f000001)
          end
        end

        describe '#to_s' do
          it 'returns binary string from value' do
            enum32.value = 2
            expect(enum32.to_s).to eq(force_binary("\x00\x00\x00\x02"))
            enum32.value = 'low'
            expect(enum32.to_s).to eq(force_binary("\x00\x00\x00\x00"))
          end

          it 'returns binary string from value, even out of range' do
            enum32.read(force_binary("\x01\x00\x00\x7f"))
            expect(enum32.to_s).to eq(force_binary("\x01\x00\x00\x7f"))
          end
        end
      end
    end

    describe Int32leEnum do
      let(:enum32le) { Int32leEnum.new(ENUM_HASH)}

      describe '#read' do
        it 'reads two bytes in enum range' do
          enum32le.read(force_binary("\x01\x00\x00\x00"))
          expect(enum32le.to_human).to eq('medium')
        end

        it 'reads two bytes, even out of range' do
          enum32le.read(force_binary("\x00\x01\x7f\x00"))
          expect(enum32le.to_human).to eq('<unknown:8323328>')
          expect(enum32le.value).to eq(0x7f0100)
        end
      end

      describe '#to_s' do
        it 'returns binary string from value' do
          enum32le.value = 2
          expect(enum32le.to_s).to eq(force_binary("\x02\x00\x00\x00"))
          enum32le.value = 'low'
          expect(enum32le.to_s).to eq(force_binary("\x00\x00\x00\x00"))
        end

        it 'returns binary string from value, even out of range' do
          enum32le.read(force_binary("\x00\x7f\x01\x00"))
          expect(enum32le.to_s).to eq(force_binary("\x00\x7f\x01\x00"))
        end
      end
    end
  end
end
