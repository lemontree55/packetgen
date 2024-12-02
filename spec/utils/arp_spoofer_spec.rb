# frozen_string_literal: true

require_relative '../spec_helper'
require 'packetgen/utils'

class TestARPSpoofer < PacketGen::Utils::ARPSpoofer
  attr_reader :all_packets

  private

  def send_packets_on_wire(packets)
    @all_packets ||= []
    @all_packets << packets
  end
end

module PacketGen
  module Utils
    describe ARPSpoofer do
      let(:as) { TestARPSpoofer.new timeout: 0.4, interval: 0.1 }

      describe '#initialize' do
        it 'accepts Integer value for timeout' do
          expect { ARPSpoofer.new timeout: 45 }.not_to raise_error
        end

        it 'accepts nil value for timeout' do
          expect { ARPSpoofer.new timeout: nil }.not_to raise_error
        end

        it 'accepts Float value for timeout' do
          expect { ARPSpoofer.new timeout: 125.5 }.not_to raise_error
        end
      end

      describe '#add' do
        it 'adds a target and a fake IP' do
          as.add '1.2.3.4', '5.6.7.8'
          as.add '1.2.3.8', '5.6.7.9'
          expect(as.registered_targets).to include('1.2.3.4', '1.2.3.8')
          expect(as.registered_targets).not_to include('5.6.7.8', '5.6.7.9')
          expect(as.active?('1.2.3.4')).to be(false)
        end

        it 'accepts options' do
          expect { as.add '1.2.3.4', '5.6.7.8', mac: '00:00:00:00:00:00' }
            .not_to raise_error
        end
      end

      describe '#remove' do
        it 'remove a target from registered targets' do
          as.add '1.2.3.4', '5.6.7.8'
          expect(as.registered_targets).to include('1.2.3.4')
          as.remove '1.2.3.4'
          expect(as.registered_targets).not_to include('1.2.3.4')
        end
      end

      describe '#start' do
        it 'adds and activates spoof on target' do
          as.start '1.2.3.4', '5.6.7.8', mac: '00:00:00:00:00:00',
                                         target_mac: '00:00:00:00:00:01'
          as.wait
          expect(as.all_packets.last.length).to eq(1)
          packet = as.all_packets.last.first
          expect(packet.arp.spa).to eq('5.6.7.8')
          expect(packet.arp.tpa).to eq('1.2.3.4')
          expect(packet.arp.sha).to eq('00:00:00:00:00:00')
          expect(packet.arp.tha).to eq('00:00:00:00:00:01')
        end
      end

      describe '#stop' do
        it 'stops spoofing on target and remove it from list' do
          as.start '1.2.3.4', '5.6.7.8', mac: '00:00:00:00:00:00',
                                         target_mac: '00:00:00:00:00:01'
          as.start '1.2.3.5', '5.6.7.9', mac: '00:00:00:00:00:02',
                                         target_mac: '00:00:00:00:00:03'
          expect(as.active_targets).to eq(as.registered_targets)
          expect(as.active_targets).to eq(['1.2.3.4', '1.2.3.5'])

          sleep(0.2)
          expect(as.all_packets.last.length).to eq(2)
          as.stop '1.2.3.4'
          expect(as.active_targets).to eq(['1.2.3.5'])
          expect(as.registered_targets).to eq(['1.2.3.5'])

          as.wait
          expect(as.all_packets.last.length).to eq(1)
          packet = as.all_packets.last.first
          expect(packet.arp.tpa).not_to eq('1.2.3.4')
        end

        it 'stops sending thread when last target is removed' do
          as.start '1.2.3.4', '5.6.7.8', mac: '00:00:00:00:00:00',
                                         target_mac: '00:00:00:00:00:01'
          sleep(0.1)
          as.stop '1.2.3.4'
          expect(as.instance_eval { @spoof_thread }).to be_nil
        end
      end

      describe '#active?' do
        it 'returns true for active target' do
          as.start '1.2.3.4', '5.6.7.8', mac: '00:00:00:00:00:00',
                                         target_mac: '00:00:00:00:00:01'
          expect(as.active?('1.2.3.4')).to be(true)
        end

        it 'returns false for inactive target' do
          as.add '1.2.3.4', '5.6.7.8', mac: '00:00:00:00:00:00',
                                       target_mac: '00:00:00:00:00:01'
          expect(as.active?('1.2.3.4')).to be(false)
        end

        it 'returns false for unknown target' do
          expect(as.active?('10.0.0.1')).to be(false)
        end
      end
    end
  end
end
