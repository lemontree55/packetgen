require 'spec_helper'
require 'packetgen/config'

module PacketGen

  describe Config do
    let(:config) { Config.instance }

    it 'gets configuration of given interface' do
      expect(config.ipaddr('lo')).to eq('127.0.0.1')
    end

    it 'gets configuration from default interface when none is given' do
      expect(config.default_iface).to match(/lo|eth|en|wl/)
      expect(config.hwaddr).to match(/[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+/)
      expect(config.ipaddr).to match(/\d+\.\d+\.\d+\.\d+/)
    end
  end
end
