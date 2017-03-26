require_relative '../spec_helper'

module PacketGen
  module Header

    describe NonESPMarker do
      describe 'bindings' do
        it 'in UDP packets with port 4500' do
          expect(UDP).to know_header(NonESPMarker).with(dport: 4500)
          expect(UDP).to know_header(NonESPMarker).with(sport: 4500)
        end
      end
    end

    describe IKE do
      describe 'bindings' do
        it 'in UDP packets with port 500' do
          expect(UDP).to know_header(IKE).with(dport: 500)
          expect(UDP).to know_header(IKE).with(sport: 500)
        end

        it 'in NonESPMarker' do
          expect(NonESPMarker).to know_header(IKE)
          expect(NonESPMarker).to know_header(IKE)
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
          expect(ike.payloads).to be_empty
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
      end

      describe '#read' do
        it 'sets header from a string' do
          ike = IKE.new
          str = (1..ike.sz).to_a.pack('C*')
          ike.read str
          expect(ike.init_spi).to eq(0x0102030405060708)
          expect(ike.resp_spi).to eq(0x090a0b0c0d0e0f10)
          expect(ike.next).to eq(0x11)
          expect(ike.version).to eq(0x12)
          expect(ike.exchange_type).to eq(0x13)
          expect(ike.flags).to eq(0x14)
          expect(ike.message_id).to eq(0x15161718)
          expect(ike.length).to eq(0x191a1b1c)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          ike = IKE.new
          str = (1..ike.sz).to_a.pack('C*')
          ike.read str
          expect(ike.to_s).to eq(str)
          expect(ike.to_s.size).to eq(28)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          ike = IKE.new
          str = ike.inspect
          expect(str).to be_a(String)
          (ike.fields - %i(body)).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      context '(parsing)' do
        let(:udp) { Packet.gen('IP').add('UDP') }

        it 'is parsed in UDP (port 500) body is null' do
          udp.add('IKE')
          str = udp.to_s
          pkt = Packet.parse(str)
          expect(pkt.is? 'UDP').to be(true)
          expect(pkt.udp.sport).to eq(500)
          expect(pkt.udp.dport).to eq(500)
          expect(pkt.is? 'IKE').to be(true)
        end

        it 'is parsed when first 32-bit word in UDP (port 4500) body is null' do
          udp.add('NonESPMarker').add('IKE')
          str = udp.to_s
          pkt = Packet.parse(str)
          expect(pkt.is? 'UDP').to be(true)
          expect(pkt.udp.sport).to eq(4500)
          expect(pkt.udp.dport).to eq(4500)
          expect(pkt.is? 'IKE').to be(true)
        end

        it 'is not parsed when first 32-bit word in UDP (port 4500) body is not null' do
          udp.udp.sport = udp.udp.dport = 4500
          udp.body = ([1] * 30).pack('C*')
          str = udp.to_s
          pkt = Packet.parse(str)
          expect(pkt.is? 'UDP').to be(true)
          expect(pkt.udp.sport).to eq(4500)
          expect(pkt.udp.dport).to eq(4500)
          expect(pkt.is? 'IKE').to be(false)
        end

        it 'also parses IKE payload' do
          packets = Packet.read(File.join(__dir__, 'ikev2.pcapng'))
          expect(packets[0].is? 'IKE').to be(true)
          ike0 = packets[0].ike
          expect(ike0.payloads).to be_a(Array)
          expect(ike0.payloads.size).to eq(5)
          expect(ike0.payloads[0]).to be_a(IKE::SA)
          expect(ike0.payloads[1]).to be_a(IKE::KE)
          expect(ike0.payloads[2]).to be_a(IKE::Nonce)
        end
      end

      context '(building)' do
        let(:ike) do
          PacketGen.gen('IP', id: 0).add('UDP').add('IKE', init_spi: 0x1234567812345678)
        end

        it 'permits to create a SA_INIT packet' do
          ike.ike.exchange_type = 34
          ike.ike.flag_i = true
          prop1 = IKE::SAProposal.new(num: 1, protocol: 'IKE')
          prop1.transforms << { type: 'ENCR', id: 'AES_GCM16' }
          prop1.transforms << { type: 'PRF', id: 'HMAC_SHA2_256' }
          prop1.transforms << { type: 'DH', id: 'ECP256' }
          prop2 = IKE::SAProposal.new(num: 2, protocol: 'IKE')
          prop2.transforms << { type: 'ENCR', id: 'AES_CTR' }
          prop2.transforms << { type: 'INTG', id: 'AES_XCBC_96' }
          prop2.transforms << { type: 'PRF', id: 'HMAC_SHA2_256' }
          prop1.transforms << { type: 'DH', id: 'MODP768' }
          ike.add('SA')
          ike.sa.proposals << prop1
          ike.sa.proposals << prop2
          ike.add('KE', group: 'ECP256', data: PacketGen.force_binary("\0" * 64))
          ike.add('Nonce', data: PacketGen.force_binary("\0" * 16))
          ike.calc_length
          ike.calc_checksum
          expected = File.read(File.join(__dir__, 'ike_sa_init.bin'))
          expect(ike.to_s).to eq(PacketGen.force_binary expected)
        end
      end
    end
  end
end
