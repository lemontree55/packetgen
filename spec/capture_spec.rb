require_relative 'spec_helper'

module PacketGen
  describe Capture do

    let(:iface) { PacketGen.default_iface }

    describe '#initialize' do
      it 'accepts no options' do
        cap = nil
        expect { cap = Capture.new(iface) }.to_not raise_error
        expect(cap).to be_a(Capture)
      end

      it 'accepts options' do
        options = { max: 12, timeout: 30, filter: 'ip', promisc: true, snaplen: 45 }
        expect { Capture.new(iface, options) }.to_not raise_error
      end
    end

    describe '#start' do
      it 'capture packets and returns a array of Packet', :sudo do
        cap = Capture.new('lo')
        cap_thread = Thread.new { cap.start }
        system 'ping 127.0.0.1 -c 3 -W 0.1 -w 1 > /dev/null'
        cap_thread.kill
        packets = cap.packets
        expect(packets).to be_a(Array)
        expect(packets.size).to eq(3)
        expect(packets.all? { |p| p.is_a? Packet }).to be(true)
      end

      it 'capture packets until :timeout seconds'
      it 'capture packets using a filter'
      it 'capture packets and returns a array of string with :parse option to false'
      it 'capture :max packets'
    end
  end
end
