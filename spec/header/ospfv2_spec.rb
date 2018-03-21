require_relative '../spec_helper'

PCAP = File.join(__dir__, 'ospfv2.pcapng')

module PacketGen
  module Header

    describe OSPFv2 do
      describe 'bindings' do
        it 'in IP packets with protocol 89' do
          expect(IP).to know_header(OSPFv2).with(protocol: 89)
        end
      end

      describe '#initialize' do
        it 'creates an OSPFv2 header with default values' do
          ospf                = OSPFv2.new
          expect(ospf.version).to eq(2)
          expect(ospf.type).to eq(1)
          expect(ospf.human_type).to eq('HELLO')
          expect(ospf.length).to eq(0)
          expect(ospf.router_id).to eq(0)
          expect(ospf.area_id).to eq(0)
          expect(ospf.checksum).to eq(0)
          expect(ospf.au_type).to eq(0)
          expect(ospf.human_au_type).to eq('NO_AUTH')
          expect(ospf.authentication).to eq(0)
        end

        it 'accepts options' do
          options             = { 
            version: 1,
            type: 'LS_ACK',
            length: 152,
            router_id: 0xffffffff,
            area_id: 0x80000000,
            checksum: 0x8001,
            au_type: 2,
            authentication: 0xff000000_00000011
          }
          ospf                = OSPFv2.new(options)
          options.each do |opt, val|
            opt               = :human_type if opt == :type
            expect(ospf.send(opt)).to eq(val)
          end
        end
      end

      describe '#read' do
        let(:ospf) { OSPFv2.new }

        it 'sets header from a string' do
          str                 = (1..ospf.sz).to_a.pack('C*')
          ospf.read(str)
          expect(ospf.version).to eq(1)
          expect(ospf.type).to eq(2)
          expect(ospf.length).to eq(0x0304)
          expect(ospf.router_id).to eq(0x05060708)
          expect(ospf.area_id).to eq(0x090a0b0c)
          expect(ospf.checksum).to eq(0x0d0e)
          expect(ospf.au_type).to eq(0x0f10)
          expect(ospf.authentication).to eq(0x11121314_15161718)
        end

        it 'reads an OSPFv2 header from a real packet' do
          raw_pkt             = PcapNG::File.new.read_packet_bytes(PCAP)[0]
          pkt                 = Packet.parse(raw_pkt)

          expect(pkt.is? 'IP').to be(true)
          expect(pkt.is? 'OSPFv2').to be(true)

          ospf                = pkt.ospfv2
          expect(ospf.version).to eq(2)
          expect(ospf.human_type).to eq('HELLO')
          expect(ospf.length).to eq(44)
          expect(ospf.router_id).to eq(0xc0a8aa08)
          expect(ospf.area_id).to eq(1)
          expect(ospf.checksum).to eq(0x273b)
          expect(ospf.human_au_type).to eq('NO_AUTH')
          expect(ospf.authentication).to eq(0)
          expect(ospf.body.to_s[0]).to eq(force_binary("\xff"))
          expect(ospf.body.to_s[-1]).to eq(force_binary("\x00"))
        end
      end

      describe '#calc_checksum' do
        it 'calculates OSPFv2 packet checksum' do
          pkt                 = PcapNG::File.new.read_packets(PCAP)[0]
          pkt.ospfv2.checksum = 0xffff
          pkt.calc_checksum
          expect(pkt.ospfv2.checksum).to eq(0x273b)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          ospf                = OSPFv2.new(router_id: 0xc0a8aa08, area_id: 1)
          ospf.calc_length
          ospf.calc_checksum

          expected            = force_binary("\x02\x01\x00\x18\xc0\xa8\xaa\x08" +
                                             "\x00\x00\x00\x01\x93\x34\x00\x00")
          expected << [0].pack('Q')
          expect(ospf.to_s).to eq(expected)
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          ospf                = OSPFv2.new
          str                 = ospf.inspect
          expect(str).to be_a(String)
          (ospf.fields - %i(body)).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe '#ospfize' do
        let(:pkt) { Packet.gen('IP').add('OSPFv2') }

        it 'sets TOS byte to internetwork control and normal service' do
          pkt.ospfize
          expect(pkt.ip.tos).to eq(0xc0)
        end

        it 'sets TTL to 1 if destination address is a mcast one' do
          pkt.ip.dst          = '224.0.0.5'
          pkt.ospfize
          expect(pkt.ip.ttl).to eq(1)
        end

        it 'sets TTL to 1 when setting a mcast destination address' do
          pkt.ospfize
          expect(pkt.ip.ttl).to_not eq(1)
          pkt.ospfize(dst: '224.0.0.6')
          expect(pkt.ip.ttl).to eq(1)
        end

        it 'accepts some well-known symbol as dst parameter' do
          pkt.ospfize(dst: :all_spf_routers)
          expect(pkt.ip.dst).to eq('224.0.0.5')
          pkt.ospfize(dst: :all_d_routers)
          expect(pkt.ip.dst).to eq('224.0.0.6')
        end
      end
    end

    describe OSPFv2 do
      let(:packets) { PacketGen.read(PCAP) }

      describe OSPFv2::Hello do
        describe '#parse' do
          it 'parses a real packet' do
            ospf = packets[0].ospfv2
            expect(ospf.type).to eq(1)
            expect(ospf.body).to be_a(OSPFv2::Hello)

            hello = ospf.body
            expect(hello.network_mask).to eq('255.255.255.0')
            expect(hello.hello_interval).to eq(10)
            expect(hello.options).to eq(2)
            expect(hello.e_opt?).to be(true)
            %w(mt mc n l dc o dn).each do |attr|
              expect(hello.send("#{attr}_opt?")).to be(false)
            end
            expect(hello.priority).to eq(1)
            expect(hello.dead_interval).to eq(40)
            expect(hello.designated_router).to eq('192.168.170.8')
            expect(hello.backup_designated_router).to eq('0.0.0.0')
            expect(hello.neighbors.size).to eq(0)

            expect(packets[1].ospfv2_hello.neighbors.size).to eq(1)
            expect(packets[1].ospfv2_hello.neighbors[0].to_human).to eq('192.168.170.2')
          end
        end
      end

      describe OSPFv2::DbDescription do
        describe '#parse' do
          it 'parses a real packet' do
            ospf = packets[2].ospfv2
            expect(ospf.type).to eq(2)
            expect(ospf.body).to be_a(OSPFv2::DbDescription)
            
            dbd = ospf.body
            expect(dbd.mtu).to eq(1500)
            expect(dbd.options).to eq(2)
            expect(dbd.flags).to eq(2)
            expect(dbd.seqnum).to eq(0x4177a97e)
            expect(dbd.lsas.size).to eq(7)
            expect(dbd.lsas[0].human_type).to eq('Router')
            expect(dbd.lsas[0].age).to eq(1)
            expect(dbd.lsas[0].options).to eq(2)
            expect(dbd.lsas[0].link_state_id).to eq('192.168.170.3')
            expect(dbd.lsas[0].advertising_router).to eq('192.168.170.3')
            expect(dbd.lsas[0].seqnum).to eq(0x80000001)
            expect(dbd.lsas[0].checksum).to eq(0x3a9c)
            expect(dbd.lsas[0].length).to eq(48)

            expect(dbd.lsas[1].human_type).to eq('AS-External')
            expect(dbd.lsas[1].age).to eq(2)
            expect(dbd.lsas[1].options).to eq(2)
            expect(dbd.lsas[1].link_state_id).to eq('80.212.16.0')
            expect(dbd.lsas[1].advertising_router).to eq('192.168.170.2')
            expect(dbd.lsas[1].seqnum).to eq(0x80000001)
            expect(dbd.lsas[1].checksum).to eq(0x2a49)
            expect(dbd.lsas[1].length).to eq(36)

            expect(dbd.lsas[6].human_type).to eq('AS-External')
            expect(dbd.lsas[6].age).to eq(2)
            expect(dbd.lsas[6].options).to eq(2)
            expect(dbd.lsas[6].link_state_id).to eq('192.168.172.0')
            expect(dbd.lsas[6].advertising_router).to eq('192.168.170.2')
            expect(dbd.lsas[6].seqnum).to eq(0x80000001)
            expect(dbd.lsas[6].checksum).to eq(0x3341)
            expect(dbd.lsas[6].length).to eq(36)
          end
        end
      end
      describe OSPFv2::LSRequest do
        describe '#parse' do
          it 'parses a real packet' do
            ospf = packets[3].ospfv2
            expect(ospf.type).to eq(3)
            expect(ospf.body).to be_a(OSPFv2::LSRequest)
            
            lsr = ospf.body
            expect(lsr.lsrs.size).to eq(7)
            expected = [{ type: 'Router',
                          link_state_id: '192.168.170.3',
                          advertising_router: '192.168.170.3'},
                          { type: 'AS-External',
                            link_state_id: '80.212.16.0',
                            advertising_router: '192.168.170.2'},
                          { type: 'AS-External',
                            link_state_id: '148.121.171.0',
                            advertising_router: '192.168.170.2'},
                          { type: 'AS-External',
                            link_state_id: '192.130.120.0',
                            advertising_router: '192.168.170.2'},
                          { type: 'AS-External',
                            link_state_id: '192.168.0.0',
                            advertising_router: '192.168.170.2'},
                          { type: 'AS-External',
                            link_state_id: '192.168.1.0',
                            advertising_router: '192.168.170.2'},
                          { type: 'AS-External',
                            link_state_id: '192.168.172.0',
                            advertising_router: '192.168.170.2'}]
            expect(lsr.lsrs.map(&:to_h)).to eq(expected)
          end
        end
      end
    end
  end
end
