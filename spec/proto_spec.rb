require_relative 'spec_helper'

module PacketGen
  describe Proto do
    it '.getprotobyname returns protoccol number from its name' do
      expect(Proto.getprotobyname('tcp')).to eq(6)
      expect(Proto.getprotobyname('udp')).to eq(17)
    end

    it '.getprotobynumber returns protoccol name from its number' do
      expect(Proto.getprotobynumber(6)).to eq('tcp')
      expect(Proto.getprotobynumber(17)).to eq('udp')
    end
  end
end
