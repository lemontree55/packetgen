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
    end
  end
end
