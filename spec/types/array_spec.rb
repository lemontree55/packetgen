require_relative '../spec_helper'

module PacketGen
  module Types
    describe Array do

      class GoodClass < Array
        set_of TLV
      end
      class GoodClass2 < Array
        def record_from_hash(obj)
          TLV.new(obj)
        end
      end
      class BadClass < Array; end
      
      context '#push' do
        let(:tlv) { TLV.new }
        let(:g) { GoodClass.new }
        let(:g2) { GoodClass.new }
        let(:b) { BadClass.new }

        it 'accepts an object' do
          expect { g << tlv }.to change { g.size }.by(1)
          expect { g2 << tlv }.to change { g2.size }.by(1)
          expect { b << tlv }.to change { b.size }.by(1)
        end

        it 'accepts a Hash when .set_of is used' do
          expect { g << { type: 1, value: '43' } }.to change { g.size }.by(1)
          expect(g.size). to eq(1)
          expect(g.first).to be_a(TLV)
          expect(g.first.type).to eq(1)
          expect(g.first.value).to eq('43')
        end

        it 'accepts a Hash when #record_from_hash is redefined' do
          expect { g2 << { type: 1, value: '43' } }.to change { g2.size }.by(1)
          expect(g2.size). to eq(1)
          expect(g2.first).to be_a(TLV)
          expect(g2.first.type).to eq(1)
          expect(g2.first.value).to eq('43')
        end

        it 'raises when a Hash is passed and .set_of is used nor #record_from_hash is redefined' do
          expect { b << { type: 1, value: '43' } }.to raise_error(NotImplementedError)
        end
      end
    end
  end
end
