require_relative '../spec_helper'

OSPFv3_PCAP = File.join(__dir__, 'ospfv3.pcapng')

module PacketGen
  module Header

    describe OSPFv3 do
      describe 'bindings' do
        it 'in IP packets with protocol 89' do
          expect(IPv6).to know_header(OSPFv3).with(next: 89)
        end
      end

      describe '#initialize' do
        it 'creates an OSPFv3 header with default values' do
          ospf                = OSPFv3.new
          expect(ospf.version).to eq(3)
          expect(ospf.type).to eq(1)
          expect(ospf.human_type).to eq('HELLO')
          expect(ospf.length).to eq(0)
          expect(ospf.router_id).to eq(0)
          expect(ospf.area_id).to eq(0)
          expect(ospf.checksum).to eq(0)
          expect(ospf.instance_id).to eq(0)
          expect(ospf.zero).to eq(0)
        end

        it 'accepts options' do
          options             = { 
            version: 45,
            type: 'LS_ACK',
            length: 152,
            router_id: 0xffffffff,
            area_id: 0x80000000,
            checksum: 0x8001,
            instance_id: 2,
          }
          ospf = OSPFv3.new(options)
          options.each do |opt, val|
            opt = :human_type if opt == :type
            expect(ospf.send(opt)).to eq(val)
          end
        end
      end

      describe '#read' do
        let(:ospf) { OSPFv3.new }

        it 'sets header from a string' do
          str = (1..ospf.sz).to_a.pack('C*')
          ospf.read(str)
          expect(ospf.version).to eq(1)
          expect(ospf.type).to eq(2)
          expect(ospf.length).to eq(0x0304)
          expect(ospf.router_id).to eq(0x05060708)
          expect(ospf.area_id).to eq(0x090a0b0c)
          expect(ospf.checksum).to eq(0x0d0e)
          expect(ospf.instance_id).to eq(0x0f)
          expect(ospf.zero).to eq(0x10)
        end

        it 'reads an OSPFv3 header from a real packet' do
          raw_pkt = PcapNG::File.new.read_packet_bytes(OSPFv3_PCAP)[0]
          pkt     = Packet.parse(raw_pkt)

          expect(pkt.is? 'IPv6').to be(true)
          expect(pkt.is? 'OSPFv3').to be(true)

          ospf = pkt.ospfv3
          expect(ospf.version).to eq(3)
          expect(ospf.human_type).to eq('HELLO')
          expect(ospf.length).to eq(36)
          expect(ospf.router_id).to eq(0x01010101)
          expect(ospf.area_id).to eq(1)
          expect(ospf.checksum).to eq(0xfb86)
          expect(ospf.instance_id).to eq(0)
          expect(ospf.body.to_s[0]).to eq(force_binary("\x00"))
          expect(ospf.body.to_s[-1]).to eq(force_binary("\x00"))
        end
      end

      describe '#calc_checksum' do
        it 'calculates OSPFv3 packet checksum' do
          pkt                 = PcapNG::File.new.read_packets(OSPFv3_PCAP)[0]
          pkt.ospfv3.checksum = 0xffff
          pkt.calc_checksum
          expect(pkt.ospfv3.checksum).to eq(0xfb86)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          pkt = Packet.gen('IPv6').add('OSPFv3', router_id: 0xc0a8aa08, area_id: 1)
          pkt.ospfv3.calc_length
          pkt.ospfv3.calc_checksum

          expected = force_binary("\x03\x01\x00\x10\xc0\xa8\xaa\x08" +
                                  "\x00\x00\x00\x01\x91\xd1\x00\x00")
          expect(pkt.ospfv3.to_s).to eq(expected)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          ospf = OSPFv3.new
          str  = ospf.inspect
          expect(str).to be_a(String)
          (ospf.fields - %i(body)).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe '#ospfize' do
        let(:pkt) { Packet.gen('IPv6').add('OSPFv3') }

        it 'sets DSCP byte to CS6' do
          pkt.ospfize
          expect(pkt.ipv6.traffic_class).to eq(0xc0)
        end

        it 'sets Hop-limit to 1 if destination address is a mcast one' do
          pkt.ipv6.dst          = 'ff02::5'
          pkt.ospfize
          expect(pkt.ipv6.hop).to eq(1)
        end

        it 'sets Hop-limit to 1 when setting a mcast destination address' do
          pkt.ospfize
          expect(pkt.ipv6.hop).to_not eq(1)
          pkt.ospfize(dst: 'ff02::5')
          expect(pkt.ipv6.hop).to eq(1)
        end

        it 'accepts some well-known symbol as dst parameter' do
          pkt.ospfize(dst: :all_spf_routers)
          expect(pkt.ipv6.dst).to eq('ff02::5')
          pkt.ospfize(dst: :all_d_routers)
          expect(pkt.ipv6.dst).to eq('ff02::6')
        end
      end
    end
  end
end
