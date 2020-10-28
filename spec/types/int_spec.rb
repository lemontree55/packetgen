require_relative '../spec_helper'
module PacketGen
  module Types
    describe Int do
      describe '#initialize' do
        it 'generates an Int with default value 0' do
          expect(Int.new.to_i).to eq(0)
          expect(Int.new.value).to be_nil
        end
        it 'generates an Int with given value' do
          expect(Int.new(42).value).to eq(42)
        end
        it 'accepts endianness as second argument' do
          int = nil
          expect { int = Int.new(42, :little) }.to_not raise_error
          expect(int.endian).to eq(:little)
        end
        it 'accepts width as third argument' do
          int = nil
          expect { int = Int.new(42, :little, 1) }.to_not raise_error
          expect(int.width).to eq(1)
        end
        it 'accepts default value as fourth argument' do
          int = nil
          expect { int = Int.new(nil, :little, 1, 5) }.to_not raise_error
          expect(int.default).to eq(5)
        end
      end

      describe '#read' do
        let(:int) { Int.new }
        it 'reads an integer and populate value' do
          int.read(42)
          expect(int.value).to eq(42)
        end
        it 'raises on reading a string' do
          expect { int.read("\x2a") }.to raise_error(ParseError)
        end
      end

      describe '#to_s' do
        it 'raises' do
          expect { Int.new.to_s }.to raise_error(StandardError, /abstract/)
        end
      end

      describe '#to_f' do
        it 'returns value as a float' do
          expect(Int.new(42).to_f).to be_within(0.1).of(42.0)
        end
      end

      context 'responds to human API' do
        let(:int) { Int.new }

        it '#from_human' do
          int.from_human 42
          expect(int.value).to eq(42)
        end

        it '#to_human' do
          int.from_human 49
          expect(int.to_human).to eq(49)
        end
      end
    end

    describe Int8 do
      let(:int) { Int8.new }
      it '#read an unsigned 8-bit integer' do
        expect(int.read("\x7f").to_i).to eq(127)
        expect(int.read("\x80").to_i).to eq(128)
      end
      it 'transforms #to_s an unsigned 8-bit integer' do
        expect(int.read(127).to_s).to eq(binary("\x7f"))
        expect(int.read(128).to_s).to eq(binary("\x80"))
      end
      it '#sz returns 1' do
        expect(int.sz).to eq(1)
      end
    end

    describe SInt8 do
      let(:int) { SInt8.new }
      it '#read a signed 8-bit integer' do
        expect(int.read("\x7f").to_i).to eq(127)
        expect(int.read("\x80").to_i).to eq(-128)
      end
      it 'transforms #to_s a signed 8-bit integer' do
        expect(int.read(127).to_s).to eq(binary("\x7f"))
        expect(int.read(-128).to_s).to eq(binary("\x80"))
      end
    end

    describe Int16 do
      let(:int) { Int16.new }
      it '#read an unsigned 16-bit big-endian integer' do
        expect(int.read("\x7f\xff").to_i).to eq(32_767)
        expect(int.read("\x80\x00").to_i).to eq(32_768)
      end
      it 'transforms #to_s an unsigned 16-bit big-endian integer' do
        expect(int.read(32_767).to_s).to eq(binary("\x7f\xff"))
        expect(int.read(32_768).to_s).to eq(binary("\x80\x00"))
      end
      it '#sz returns 2' do
        expect(int.sz).to eq(2)
      end
    end

    describe Int16le do
      let(:int) { Int16le.new }
      it '#read an unsigned 16-bit little-endian integer' do
        expect(int.read("\xff\x7f").to_i).to eq(32_767)
        expect(int.read("\x00\x80").to_i).to eq(32_768)
      end
      it 'transforms #to_s an unsigned 16-bit little-endian integer' do
        expect(int.read(32_767).to_s).to eq(binary("\xff\x7f"))
        expect(int.read(32_768).to_s).to eq(binary("\x00\x80"))
      end
    end

    describe SInt16 do
      let(:int) { SInt16.new }
      it '#read a signed 16-bit big-endian integer' do
        expect(int.read("\x7f\xff").to_i).to eq(32_767)
        expect(int.read("\x80\x00").to_i).to eq(-32_768)
      end
      it 'transforms #to_s a signed 16-bit big-endian integer' do
        expect(int.read(32_767).to_s).to eq(binary("\x7f\xff"))
        expect(int.read(-32_768).to_s).to eq(binary("\x80\x00"))
      end
    end

    describe SInt16le do
      let(:int) { SInt16le.new }
      it '#read a signed 16-bit little-endian integer' do
        expect(int.read("\xff\x7f").to_i).to eq(32_767)
        expect(int.read("\x00\x80").to_i).to eq(-32_768)
      end
      it 'transforms #to_s a signed 16-bit little-endian integer' do
        expect(int.read(32_767).to_s).to eq(binary("\xff\x7f"))
        expect(int.read(-32_768).to_s).to eq(binary("\x00\x80"))
      end
    end

    describe Int24 do
      let(:int) { Int24.new }
      let(:strint1) { binary("\x7f\xff\xff") }
      let(:strint2) { binary("\x80\x00\x00") }
      it '#read an unsigned 24-bit big-endian integer' do
        expect(int.read(strint1).to_i).to eq(0x7f_ffff)
        expect(int.read(strint2).to_i).to eq(0x80_0000)
      end
      it 'transforms #to_s an unsigned 24-bit big-endian integer' do
        expect(int.read(0x7f_ffff).to_s).to eq(strint1)
        expect(int.read(0x80_0000).to_s).to eq(strint2)
      end
      it '#sz returns 3' do
        expect(int.sz).to eq(3)
      end
    end

    describe Int24le do
      let(:int) { Int24le.new }
      let(:strint1) { binary("\xff\xff\x7f") }
      let(:strint2) { binary("\x00\x00\x80") }
      it '#read an unsigned 24-bit little-endian integer' do
        expect(int.read(strint1).to_i).to eq(0x7f_ffff)
        expect(int.read(strint2).to_i).to eq(0x80_0000)
      end
      it 'transforms #to_s an unsigned 24-bit little-endian integer' do
        expect(int.read(0x7f_ffff).to_s).to eq(strint1)
        expect(int.read(0x80_0000).to_s).to eq(strint2)
      end
    end

    describe Int32 do
      let(:int) { Int32.new }
      it '#read an unsigned 32-bit big-endian integer' do
        expect(int.read("\x7f\xff\xff\xff").to_i).to eq(0x7fff_ffff)
        expect(int.read("\x80\x00\x00\x00").to_i).to eq(0x8000_0000)
      end
      it 'transforms #to_s an unsigned 32-bit big-endian integer' do
        expect(int.read(0x7fff_ffff).to_s).to eq(binary("\x7f\xff\xff\xff"))
        expect(int.read(0x8000_0000).to_s).to eq(binary("\x80\x00\x00\x00"))
      end
      it '#sz returns 4' do
        expect(int.sz).to eq(4)
      end
    end

    describe Int32le do
      let(:int) { Int32le.new }
      it '#read an unsigned 32-bit little-endian integer' do
        expect(int.read("\xff\xff\xff\x7f").to_i).to eq(0x7fff_ffff)
        expect(int.read("\x00\x00\x00\x80").to_i).to eq(0x8000_0000)
      end
      it 'transforms #to_s an unsigned 32-bit little-endian integer' do
        expect(int.read(0x7fff_ffff).to_s).to eq(binary("\xff\xff\xff\x7f"))
        expect(int.read(0x8000_0000).to_s).to eq(binary("\x00\x00\x00\x80"))
      end
    end

    describe SInt32 do
      let(:int) { SInt32.new }
      it '#read a signed 32-bit big-endian integer' do
        expect(int.read("\x7f\xff\xff\xff").to_i).to eq(0x7fff_ffff)
        expect(int.read("\x80\x00\x00\x00").to_i).to eq(-0x8000_0000)
      end
      it 'transforms #to_s a signed 32-bit big-endian integer' do
        expect(int.read(0x7fff_ffff).to_s).to eq(binary("\x7f\xff\xff\xff"))
        expect(int.read(-0x8000_0000).to_s).to eq(binary("\x80\x00\x00\x00"))
      end
    end

    describe SInt32le do
      let(:int) { SInt32le.new }
      it '#read a signed 32-bit little-endian integer' do
        expect(int.read("\xff\xff\xff\x7f").to_i).to eq(0x7fff_ffff)
        expect(int.read("\x00\x00\x00\x80").to_i).to eq(-0x8000_0000)
      end
      it 'transforms #to_s a signed 32-bit little-endian integer' do
        expect(int.read(0x7fff_ffff).to_s).to eq(binary("\xff\xff\xff\x7f"))
        expect(int.read(-0x8000_0000).to_s).to eq(binary("\x00\x00\x00\x80"))
      end
    end

    INT64 = {
      big: {
        unsigned: [
          {
            int: 0x7fff_ffff_ffff_ffff,
            str: "\x7f\xff\xff\xff\xff\xff\xff\xff"
          },
          {
            int: 0x8000_0000_0000_0000,
            str: "\x80\x00\x00\x00\x00\x00\x00\x00"
          }
        ],
        signed: [
          {
            int: 0x7fff_ffff_ffff_ffff,
            str: "\x7f\xff\xff\xff\xff\xff\xff\xff"
          },
          {
            int: -0x8000_0000_0000_0000,
            str: "\x80\x00\x00\x00\x00\x00\x00\x00"
          }
        ]
      },
      little: {
        unsigned: [
          {
            int: 0x7fff_ffff_ffff_ffff,
            str: "\xff\xff\xff\xff\xff\xff\xff\x7f"
          },
          {
            int: 0x8000_0000_0000_0000,
            str: "\x00\x00\x00\x00\x00\x00\x00\x80"
          }
        ],
        signed: [
          {
            int: 0x7fff_ffff_ffff_ffff,
            str: "\xff\xff\xff\xff\xff\xff\xff\x7f"
          },
          {
            int: -0x8000_0000_0000_0000,
            str: "\x00\x00\x00\x00\x00\x00\x00\x80"
          }
        ]
      }
    }

    %i[unsigned signed].each do |us|
      %i[big little].each do |endian|
        suffix = endian == :little ? 'le': ''
        prefix = us == :signed ? 'S' : ''
        klass = Types.const_get("#{prefix}Int64#{suffix}")
        describe klass do
          before(:each) { @int = klass.new }
          it "#read an unsigned 64-bit #{endian}-endian integer" do
            fixtures = INT64[endian][us]
            expect(@int.read(fixtures[0][:str]).to_i).to eq(fixtures[0][:int])
            expect(@int.read(fixtures[1][:str]).to_i).to eq(fixtures[1][:int])
          end
          it "transforms #to_s an unsigned 64-bit #{endian}-endian integer" do
            fixtures = INT64[endian][us]
            expect(@int.read(fixtures[0][:int]).to_s).to eq(binary(fixtures[0][:str]))
            expect(@int.read(fixtures[1][:int]).to_s).to eq(binary(fixtures[1][:str]))
          end
          it '#sz returns 8' do
            expect(@int.sz).to eq(8)
          end
        end
      end
    end
  end
end
