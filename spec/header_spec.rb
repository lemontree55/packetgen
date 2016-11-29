module PacketGen

  describe Header do
    it '.all returns all header classes' do
      expect(Header.all).to eq([Header::Eth, Header::IP, Header::UDP])
    end
  end
end
