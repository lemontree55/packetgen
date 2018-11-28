require_relative '../spec_helper'

module PacketGen
  module Types
    describe Array do

      MyTLV = AbstractTLV.create(type_class: Int8)
      class GoodClass < Array
        set_of MyTLV
      end
      class GoodClass2 < Array
        def record_from_hash(obj)
          MyTLV.new(obj)
        end
      end
      class BadClass < Array; end

      let(:tlv) { MyTLV.new }

      context '#push' do
        let(:g) { GoodClass.new }
        let(:g2) { GoodClass.new }
        let(:b) { BadClass.new }

        it 'accepts an object' do
          expect { g.push tlv }.to change { g.size }.by(1)
          expect { g2.push tlv }.to change { g2.size }.by(1)
          expect { b.push tlv }.to change { b.size }.by(1)
        end

        it 'accepts a Hash when .set_of is used' do
          expect { g << { type: 1, value: '43' } }.to change { g.size }.by(1)
          expect(g.size). to eq(1)
          expect(g.first).to be_a(MyTLV)
          expect(g.first.type).to eq(1)
          expect(g.first.value).to eq('43')
        end

        it 'accepts a Hash when #record_from_hash is redefined' do
          expect { g2 << { type: 1, value: '43' } }.to change { g2.size }.by(1)
          expect(g2.size). to eq(1)
          expect(g2.first).to be_a(MyTLV)
          expect(g2.first.type).to eq(1)
          expect(g2.first.value).to eq('43')
        end

        it 'raises when a Hash is passed and .set_of is used nor #record_from_hash is redefined' do
          expect { b << { type: 1, value: '43' } }.to raise_error(NotImplementedError)
        end

        it 'does not update counter if one was declared at initialization' do
          int32 = Int32.new
          ary = Array.new(counter: int32)
          expect { ary.push tlv }.to_not change { int32.to_i }
        end
      end

      context '#<<' do
        it 'updates counter if one was declared at initialization' do
          int32 = Int32.new
          ary = Array.new(counter: int32)
          expect { ary << tlv }.to change { int32.to_i }.by(1)
        end
      end

      context '#delete' do
        it 'updates counter if one was declared at initialization' do
          int32 = Int32.new
          ary = Array.new(counter: int32)
          ary << tlv
          expect { ary.delete tlv }.to change { int32.to_i }.by(-1)
        end
      end
    end
  end
end
