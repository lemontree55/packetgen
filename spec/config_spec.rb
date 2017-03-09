require 'spec_helper'
require 'packetgen/config'

module PacketGen

  describe Config do
    describe '#initialize' do
      it 'gets configuration of given interface' do
        cfg = Config.new('lo')
        expect(cfg.iface).to eq('lo')
        expect(cfg.ipaddr).to eq('127.0.0.1')
      end

      it 'gets configuration from first available interface when none is given' do
        cfg = Config.new
        expect(cfg.iface).to match(/lo|eth0|en0|wlan/)
        expect(cfg.hwaddr).to match(/[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+/)
        expect(cfg.ipaddr).to match(/\d+\.\d+\.\d+\.\d+/)
      end
    end
  end
end
