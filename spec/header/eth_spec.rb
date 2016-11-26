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
    end
  end
end
