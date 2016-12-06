require_relative '../spec_helper'

module PacketGen
  module Header

    describe Eth::MacAddr do
      before(:each) do
        @mac = Eth::MacAddr.new.parse('00:01:02:03:04:05')
      end

      it '#parse a MAC address string' do
        expect(@mac.a0).to eq(0)
        expect(@mac.a1).to eq(1)
        expect(@mac.a2).to eq(2)
        expect(@mac.a3).to eq(3)
        expect(@mac.a4).to eq(4)
        expect(@mac.a5).to eq(5)
      end

      it '#to_x returns a MAC address string' do
        expect(@mac.to_x).to eq('00:01:02:03:04:05')
      end
    end

    describe Eth do

      describe '#initialize' do
        it 'creates a Ethernet header with default values' do
          eth = Eth.new
          expect(eth).to be_a(Eth)
          expect(eth.dst).to eq('00:00:00:00:00:00')
          expect(eth.src).to eq('00:00:00:00:00:00')
          expect(eth.proto).to eq(0)
        end

        it 'accepts options' do
          options = {
            dst: '00:01:02:03:04:05',
            src: '00:ff:ff:ff:ff:4c',
            proto: 0x800,
            body: 'this is a body'
          }
          eth = Eth.new(options)
          options.each do |key, value|
            expect(eth.send(key)).to eq(value)
          end
        end
      end

      describe '#read' do
        let(:eth) { Eth.new}

        it 'sets header from a string' do
          str = (0...eth.sz).to_a.pack('C*') + 'body'
          eth.read str
          expect(eth.dst).to eq('00:01:02:03:04:05')
          expect(eth.src).to eq('06:07:08:09:0a:0b')
          expect(eth.proto).to eq(0x0c0d)
          expect(eth.body).to eq('body')
        end

        it 'raises when str is too short' do
          expect { eth.read 'abcd' }.to raise_error(ParseError, /too short/)
          expect { eth.read('abcdef' * 2) }.to raise_error(ParseError, /too short/)
        end
      end

      describe 'setters' do
        before(:each) do
          @eth = Eth.new
        end

        it '#dst= accepts a MAC address string' do
          @eth.dst = 'ff:fe:fd:fc:fb:fa'
          6.times do |i|
            expect(@eth[:dst]["a#{i}".to_sym].to_i).to eq(0xff - i)
          end
        end

        it '#src= accepts a MAC address string' do
          @eth.src = 'ff:fe:fd:fc:fb:fa'
          6.times do |i|
            expect(@eth[:src]["a#{i}".to_sym].to_i).to eq(0xff - i)
          end
        end

        it '#proto= accepts an integer' do
          @eth.proto = 0xabcd
          expect(@eth[:proto].value).to eq(0xabcd)
        end
      end

      describe '#to_w' do
        it 'responds to #to_w' do
          expect(Eth.new).to respond_to(:to_w)
        end

        it 'send a Eth header on wire', :sudo do
          body = PacketGen.force_binary("\x00" * 64)
          pkt = Packet.gen('Eth', dst: 'ff:ff:ff:ff:ff:ff',
                           src: 'ff:ff:ff:ff:ff:ff').add('IP', body: body)
          Thread.new { sleep 1; pkt.eth.to_w('eth0') }
          packets = Packet.capture('eth0', max: 1,
                                   filter: 'ether dst ff:ff:ff:ff:ff:ff',
                                   timeout: 2)
          packet = packets.first
          expect(packet.is? 'Eth').to be(true)
          expect(packet.eth.dst).to eq('ff:ff:ff:ff:ff:ff')
          expect(packet.eth.src).to eq('ff:ff:ff:ff:ff:ff')
          expect(packet.eth.proto).to eq(0x0800)
          expect(packet.ip.body).to eq(body)
        end
      end

      it '#to_s returns a binary string' do
        ethx = Eth.new(dst: '00:01:02:03:04:05', proto: 0x800).to_s
        expected = PacketGen.force_binary("\x00\x01\x02\x03\x04\x05" \
                                          "\x00\x00\x00\x00\x00\x00\x08\x00")
        expect(ethx).to eq(expected)
      end
    end
  end
end
