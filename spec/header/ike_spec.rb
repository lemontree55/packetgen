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

      describe '#initialize' do
        it 'creates a IKE header with default values' do
          ike = IKE.new
          expect(ike.init_spi).to eq(0)
          expect(ike.resp_spi).to eq(0)
          expect(ike.next).to eq(0)
          expect(ike.version).to eq(0x20)
          expect(ike.exchange_type).to eq(0)
          expect(ike.flags).to eq(0)
          expect(ike.message_id).to eq(0)
          expect(ike.length).to eq(28)
        end

        it 'accepts options' do
          options = {
            init_spi: 0x00010203_04050607,
            resp_spi: 0x08090a0b_0c0d0e0f,
            next: 255,
            version: 0x50,
            exchange_type: 240,
            flags: 0x80,
            message_id: 0x12345678,
            length: 0x400
          }
          ike = IKE.new(options)
          options.each do |opt, value|
            expect(ike.send(opt)).to eq(value)
          end
        end

        it 'accepts non_esp_marker option' do
          options = {
            non_esp_marker: 0,
            init_spi: 0x00010203_04050607,
            resp_spi: 0x08090a0b_0c0d0e0f,
            next: 255,
            version: 0x50,
            exchange_type: 240,
            flags: 0x80,
            message_id: 0x12345678,
            length: 0x400
          }
          ike = IKE.new(options)
          options.each do |opt, value|
            expect(ike.send(opt)).to eq(value)
          end
        end
      end

      describe '#read' do
        it 'sets header from a string (without non_esp_marker)' do
          ike = IKE.new
          str = (1..ike.sz).to_a.pack('C*')
          ike.read str
          expect(ike.non_esp_marker).to eq(0)
          expect(ike.init_spi).to eq(0x0102030405060708)
          expect(ike.resp_spi).to eq(0x090a0b0c0d0e0f10)
          expect(ike.next).to eq(0x11)
          expect(ike.version).to eq(0x12)
          expect(ike.exchange_type).to eq(0x13)
          expect(ike.flags).to eq(0x14)
          expect(ike.message_id).to eq(0x15161718)
          expect(ike.length).to eq(0x191a1b1c)
        end

        it 'sets header from a string (with non_esp_marker)' do
          ike = IKE.new(non_esp_marker: 0)
          str = (1..ike.sz).to_a.pack('C*')
          ike.read str
          expect(ike.non_esp_marker).to eq(0x01020304)
          expect(ike.init_spi).to eq(0x05060708090a0b0c)
          expect(ike.resp_spi).to eq(0x0d0e0f1011121314)
          expect(ike.next).to eq(0x15)
          expect(ike.version).to eq(0x16)
          expect(ike.exchange_type).to eq(0x17)
          expect(ike.flags).to eq(0x18)
          expect(ike.message_id).to eq(0x191a1b1c)
          expect(ike.length).to eq(0x1d1e1f20)
        end
      end

      describe '#to_s' do
        it 'returns a binary string (without non_esp_marker)' do
          ike = IKE.new
          str = (1..ike.sz).to_a.pack('C*')
          ike.read str
          expect(ike.to_s).to eq(str)
          expect(ike.to_s.size).to eq(28)
        end

        it 'returns a binary string (with non_esp_marker)' do
          ike = IKE.new(non_esp_marker: 0)
          str = (1..ike.sz).to_a.pack('C*')
          ike.read str
          expect(ike.to_s).to eq(str)
          expect(ike.to_s.size).to eq(32)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes (without non_esp_marker)' do
          ike = IKE.new
          str = ike.inspect
          expect(str).to be_a(String)
          expect(ike.fields).to_not include(:non_esp_marker)
          ike.fields.each do |attr|
            expect(str).to include(attr.to_s)
          end
        end

        it 'returns a String with all attributes (with non_esp_marker)' do
          ike = IKE.new(non_esp_marker: 0)
          str = ike.inspect
          expect(str).to be_a(String)
          expect(ike.fields).to include(:non_esp_marker)
          ike.fields.each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      context '(parsing)' do
        let(:udp) { Packet.gen('IP').add('UDP') }

        it 'is parsed in UDP (port 500) body is null'
        it 'is parsed when first 32-bit word in UDP (port 4500) body is null'
        it 'is not parsed when first 32-bit word in UDP (port 4500) body is not null'
      end
    end
  end
end
