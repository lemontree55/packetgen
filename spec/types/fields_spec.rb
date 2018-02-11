require_relative '../spec_helper'

module PacketGen
  module Types
    describe Fields do

      class FTest < Fields; end

      after(:each) do
        FTest.class_eval { @ordered_fields.clear; @field_defs.clear; @bit_fields.clear }
      end

      describe '.define_field' do
        it 'adds a field to class' do
          expect(FTest.new.fields).to be_empty
          FTest.class_eval { define_field :f1, Int8 }
          expect(FTest.new.fields).to eq([:f1])
        end

        it 'adds a field with specified type' do
          FTest.class_eval { define_field :f1, Int8 }
          ft = FTest.new
          expect(ft[:f1]).to be_a(Int8)
          expect(ft.f1).to be_a(Integer)
          ft.f1 = 123
          expect(ft[:f1].value).to eq(123)

          FTest.class_eval { define_field :f2, Int32 }
          ft = FTest.new
          expect(ft[:f2]).to be_a(Int32)
          expect(ft.f2).to be_a(Integer)
          ft.f2 = 1234
          expect(ft[:f2].value).to eq(1234)

          FTest.class_eval { define_field :f3, String }
          ft = FTest.new
          expect(ft[:f3]).to be_a(String)
          expect(ft.f3).to be_a(String)
          expect(ft.f3).to be_a(String)
          ft.f3 = 'abcd'
          expect(ft[:f3]).to eq('abcd')
        end

        it 'adds a field with default value' do
          FTest.class_eval { define_field :f1, Int8, default: 255 }
          expect(FTest.new.f1).to eq(255)

          FTest.class_eval { define_field :f2, Int16, default: -> { rand(8) +1 } }
          expect(FTest.new.f2).to be > 0
          expect(FTest.new.f2).to be < 9
        end

        it 'adds a field with given builder' do
          FTest.class_eval { define_field :f1, Int8, builder: ->(x,t) { Int16.new } }
          expect(FTest.new[:f1]).to be_a(Int16)
        end
      end

      describe '.define_field_before' do
        before(:each) do
          FTest.class_eval { define_field :f1, Int8; define_field :f2, Int8 }
        end

        it 'adds a field before another one' do
          FTest.class_eval { define_field_before :f1, :f3, Int8 }
          expect(FTest.new.fields).to eq([:f3, :f1, :f2])

          FTest.class_eval { define_field_before :f2, :f4, Int8 }
          expect(FTest.new.fields).to eq([:f3, :f1, :f4, :f2])
        end

        it 'raises on unknown before field' do
          expect { FTest.class_eval { define_field_before :unk, :f3, Int8 } }.
            to raise_error(ArgumentError, 'unknown unk field')
        end
      end

      describe '.define_field_after' do
        before(:each) do
          FTest.class_eval { define_field :f1, Int8; define_field :f2, Int8 }
        end

        it 'adds a field after another one' do
          FTest.class_eval { define_field_after :f1, :f3, Int8 }
          expect(FTest.new.fields).to eq([:f1, :f3, :f2])

          FTest.class_eval { define_field_after :f2, :f4, Int8 }
          expect(FTest.new.fields).to eq([:f1, :f3, :f2, :f4])
        end

        it 'raises on unknown after field' do
          expect { FTest.class_eval { define_field_after :unk, :f3, Int8 } }.
            to raise_error(ArgumentError, 'unknown unk field')
        end
      end

      describe '.define_bit_fields_on' do
        before(:each) do
          FTest.class_eval { define_field :u8, Int8 }
        end

        it 'adds bit fields on an Int attribute' do
          FTest.class_eval do
            define_bit_fields_on :u8, :b0, :b1, :b2, :b3, :b4, :b5, :b6, :b7
          end
          ft = FTest.new
          8.times do |i|
            expect(ft).to respond_to("b#{i}?".to_sym)
            expect(ft).to respond_to("b#{i}=".to_sym)
          end

          expect(ft.u8).to eq(0)
          ft.u8 = 0x40
          expect(ft.b0?).to be(false)
          expect(ft.b1?).to be(true)
          expect(ft.b2?).to be(false)

          ft.b7 = true
          ft.b1 = false
          expect(ft.u8).to eq(1)
        end

        it 'adds muliple-bit fields on an Int attribute' do
          FTest.class_eval do
            define_bit_fields_on :u8, :f1, 4, :f2, :f3, 3
          end
          ft = FTest.new
          expect(ft).to respond_to(:f1)
          expect(ft).to respond_to(:f1=)
          expect(ft).to respond_to(:f2?)
          expect(ft).to respond_to(:f2=)
          expect(ft).to respond_to(:f3)
          expect(ft).to respond_to(:f3=)
          ft.u8 = 0xc9
          expect(ft.f1).to eq(0xc)
          expect(ft.f2?).to eq(true)
          expect(ft.f3).to eq(1)
          ft.f1 = 0xf
          ft.f2 = false
          ft.f3 = 7
          expect(ft.u8).to eq(0xf7)
        end

        it 'raises on unknown attribute' do
          expect { FTest.class_eval { define_bit_fields_on :unk, :bit } }.
            to raise_error(ArgumentError, 'unknown unk field')
        end

        it 'raises on non-Int attribute' do
          FTest.class_eval { define_field :f1, Types::String }
          expect { FTest.class_eval { define_bit_fields_on :f1, :bit } }.
            to raise_error(TypeError, 'f1 is not a PacketGen::Types::Int')
        end
      end

      context 'may define an optional field' do
        class FOptional < Fields
          define_field :u8, Types::Int32
          define_bit_fields_on :u8, :present, :others, 31
          define_field :optional, Types::Int32, optional: ->(fo) { fo.present? }
        end

        let(:f) { FOptional.new }

        it 'which is listed in optional fields' do
          expect(f.is_optional?(:optional)).to be(true)
          expect(f.optional_fields).to include(:optional)
          expect(f.optional_fields).to_not include(:u8)
        end

        it 'which may be parsed' do
          f.read(force_binary("\x80\x00\x00\x00\x01\x23\x45\x67"))
          expect(f.present?).to be(true)
          expect(f.optional).to eq(0x1234567)
        end

        it 'which may be not parsed' do
          f.read(force_binary("\x00\x00\x00\x00\x01\x23\x45\x67"))
          expect(f.present?).to be(false)
          expect(f.optional).to eq(0)
        end

        it 'which may be serialized' do
          f.present = true
          f.optional = 0x89abcdef
          expect(f.to_s).to eq(force_binary("\x80\x00\x00\x00\x89\xab\xcd\xef"))
        end

        it 'which may be not serialized' do
          f.present = false
          f.optional = 0x89abcdef
          expect(f.to_s).to eq(force_binary("\x00\x00\x00\x00"))
        end
      end
    end
  end
end
