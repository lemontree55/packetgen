require_relative '../spec_helper'

module PacketGen
  module Header
    class TCP
      describe Option do

        describe '#initialize' do
          it 'creates a TCP option' do
            opt = Option.new
            expect(opt.kind).to eq(0)
            expect(opt[:length].value).to be(nil)
            expect(opt[:value]).to be_a(Types::String)
          end

          it 'infers correct Int subclass when value is an integer' do
            opt = Option.new(length: 3, value: 0x80)
            expect(opt[:value]).to be_a(Types::Int8)
            expect(opt.value).to eq(0x80)

            opt = Option.new(length: 4, value: 0x8000)
            expect(opt[:value]).to be_a(Types::Int16)
            expect(opt.value).to eq(0x8000)

            opt = Option.new(length: 6, value: 0x80000000)
            expect(opt[:value]).to be_a(Types::Int32)
            expect(opt.value).to eq(0x80000000)
          end

          it 'sets length attribute from value if the latter is a String' do
            opt = Option.new(value: 'abcd')
            expect(opt.value).to eq('abcd')
            expect(opt.length).to eq(6)
          end

          it 'sets argument length, even if value is a String' do
            opt = Option.new(value: 'abcdefghij', length: 18)
            expect(opt.value).to eq('abcdefghij')
            expect(opt.length).to eq(18)
          end

          it 'raises on bad length value for integer value' do
            expect { Option.new(value: 0, length: 5) }.to raise_error(ArgumentError)
          end
        end

        describe '#read' do
          it 'reads an integer Option' do
            opt = Option.new.read("\xfd\x06\x00\x00\x00\x01")
            expect(opt.kind).to eq(253)
            expect(opt.length).to eq(6)
            expect(opt.value).to eq(force_binary "\x00\x00\x00\x01")
          end

          it 'reads a long Option' do
            opt = Option.new.read("\x20\x09abcdefg")
            expect(opt.kind).to eq(32)
            expect(opt.length).to eq(9)
            expect(opt.value).to eq('abcdefg')
          end
        end

        describe '#to_s' do
          it 'generates a string for Option with only a kind' do
            opt = Option.new(kind: 1)
            expect(opt.to_s).to eq(force_binary "\x01")
          end

          it 'generates a string for complete Option' do
            opt = Option.new(kind: 253, length: 4, value: 1)
            expected = "\xfd\x04\x00\x01"
            expect(opt.to_s).to eq(force_binary expected)

            opt = Option.new(kind: 253, length: 6, value: 1)
            expected = "\xfd\x06\x00\x00\x00\x01"
            expect(opt.to_s).to eq(force_binary expected)

            opt = Option.new(kind: 32, value: 'abcdefg')
            expected = "\x20\x09abcdefg"
            expect(opt.to_s).to eq(force_binary expected)
          end
        end
      end

      describe EOL do
        it 'kind is 0' do
          expect(EOL.new.kind).to eq(0)
        end

        it 'is a single byte option' do
          expect(EOL.new.to_s).to eq("\x00")
        end
      end

      describe NOP do
        it 'kind is 1' do
          expect(NOP.new.kind).to eq(1)
        end

        it 'is a single byte option' do
          expect(NOP.new.to_s).to eq(force_binary "\x01")
        end
      end

      describe MSS do
        it 'kind is 2' do
          expect(MSS.new.kind).to eq(2)
        end

        it 'is a 4-byte option' do
          mss = MSS.new
          expect(mss.to_s).to eq(force_binary "\x02\x04\x00\x00")
          mss.value = 0x123
          expect(mss.to_s).to eq(force_binary "\x02\x04\x01\x23")
        end
      end

      describe WS do
        it 'kind is 3' do
          expect(WS.new.kind).to eq(3)
        end

        it 'is a 3-byte option' do
          ws = WS.new
          expect(ws.to_s).to eq(force_binary "\x03\x03\x00")
          ws.value = 0x12
          expect(ws.to_s).to eq(force_binary "\x03\x03\x12")
        end
      end

      describe SACKOK do
        it 'kind is 4' do
          expect(SACKOK.new.kind).to eq(4)
        end

        it 'is a 2-byte option' do
          expect(SACKOK.new.to_s).to eq(force_binary "\x04\x02")
        end
      end

      describe SACK do
        it 'kind is 5' do
          expect(SACK.new.kind).to eq(5)
        end

        it 'is a multi-byte option' do
          sack = SACK.new
          expect(sack.to_s).to eq(force_binary "\x05\x02")
          1.upto(12) do |i|
            sack.value = 'z' * i
            expected = [5, 2 + i].pack('C*') + 'z' * i
            expect(sack.to_s).to eq(force_binary expected)
          end
        end
      end

      describe ECHO do
        it 'kind is 6' do
          expect(ECHO.new.kind).to eq(6)
        end

        it 'is a 6-byte option' do
          echo = ECHO.new
          expect(echo.to_s).to eq(force_binary "\x06\x06\x00\x00\x00\x00")
          echo.value = 0xff010203
          expect(echo.to_s).to eq(force_binary "\x06\x06\xff\x01\x02\x03")
        end
      end

      describe ECHOREPLY do
        it 'kind is 7' do
          expect(ECHOREPLY.new.kind).to eq(7)
        end

        it 'is a 6-byte option' do
          echor = ECHOREPLY.new
          expect(echor.to_s).to eq(force_binary "\x07\x06\x00\x00\x00\x00")
          echor.value = 0xff010203
          expect(echor.to_s).to eq(force_binary "\x07\x06\xff\x01\x02\x03")
        end
      end

      describe TS do
        it 'kind is 8' do
          expect(TS.new.kind).to eq(8)
        end

        it 'is a 10-byte option' do
          ts = TS.new
          expect(ts.to_s).to eq(force_binary("\x08\x0a" + "\x00" * 8))
          ts.value = "\x7f" + "\x01" * 7
          expect(ts.to_s).to eq(force_binary("\x08\x0a\x7f" + "\x01" * 7))
        end
      end
    end
  end
end
