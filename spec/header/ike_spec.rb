require_relative '../spec_helper'

module PacketGen
  module Header

    describe IKE do
      describe 'bindings' do
        it 'in UDP packets with port 500' do
          expect(UDP).to know_header(IKE).with(dport: 500)
          expect(UDP).to know_header(IKE).with(sport: 500)
        end

        it 'in UDP packets with port 4500' do
          expect(UDP).to know_header(IKE).with(dport: 4500)
          expect(UDP).to know_header(IKE).with(sport: 4500)
        end
      end

      describe '#initialize' do
        it 'creates a IKE header with default values'
        it 'accepts options'
      end

      describe '#read' do
        let(:ike) { IKE.new }

        it 'sets header from a string'
        it 'also sets ICV when ICV length was previously set'
      end

      describe '#to_s' do
        it 'returns a binary string'
      end

      describe '#inspect' do
        it 'returns a String with all attributes'
      end

      context '(parsing)' do
        it 'is parsed when first 32-bit word in UDP body is null'
        it 'is not parsed when first 32-bit word in UDP body is not null'
      end
    end
  end
end
