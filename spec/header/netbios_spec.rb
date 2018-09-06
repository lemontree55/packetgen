require_relative '../spec_helper'

module PacketGen
  module Header
    module NetBIOS
      describe Name do
        let(:name) { Name.new }

        describe '#from_human' do
          it 'encodes a NetBIOS name' do
            name.from_human('The NetBIOS name')
            expect(name.to_s).to eq(force_binary("\x20FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF\x00"))
          end
          it 'encodes a NetBIOS name with a scope ID' do
            name.from_human('FRED.NETBIOS.COM')
            expect(name.to_s).to eq(force_binary("\x20EGFCEFEECACACACACACACACACACACACA\x07NETBIOS\x03COM\x00"))
          end
        end

        describe '#to_human' do
          it 'decodes a NetBIOS name' do
            name.read(force_binary("\x20EGFCEFEECACACACACACACACACACACACA\x07NETBIOS\x03COM\x00"))
            expect(name.to_human).to eq('FRED')
          end
        end
      end

      describe Session do
        describe 'bindings' do
          it 'in TCP packets with source or destination port 139' do
            expect(TCP).to know_header(Session).with(sport: 139)
            expect(TCP).to know_header(Session).with(dport: 139)
          end
        end
      end
    end
  end
end
