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

    describe OSPFv3 do
      let(:packets) { PacketGen.read(OSPFv3_PCAP) }

      describe OSPFv3::Hello do
        describe '#parse' do
          it 'parses a real packet' do
            ospf = packets[0].ospfv3
            expect(ospf.version).to eq(3)
            expect(ospf.type).to eq(1)
            expect(ospf.body).to be_a(OSPFv3::Hello)

            hello = ospf.body
            expect(hello.interface_id).to eq(5)
            expect(hello.priority).to eq(1)
            expect(hello.options).to eq(0x000013)
            expect(hello.r_opt?).to be(true)
            expect(hello.e_opt?).to be(true)
            expect(hello.v6_opt?).to be(true)
            %w(x n dc).each do |attr|
              expect(hello.send("#{attr}_opt?")).to be(false)
            end
            expect(hello.hello_interval).to eq(10)
            expect(hello.dead_interval).to eq(40)
            expect(hello.designated_router).to eq('0.0.0.0')
            expect(hello.backup_designated_router).to eq('0.0.0.0')
            expect(hello.neighbors.size).to eq(0)

            expect(packets[1].ospfv3_hello.neighbors.size).to eq(1)
            expect(packets[1].ospfv3_hello.neighbors[0].to_human).to eq('2.2.2.2')
          end
        end
      end

      #describe OSPFv3::LSAHeader do
      #  describe '#calc_checksum' do
      #    it 'calculates Fletcher-16 checksum' do
      #      lsa = packets[5].ospfv3_lsupdate.lsas.first
      #      checksum = lsa.checksum
      #      lsa.checksum = 0xffff
      #      lsa.calc_checksum
      #      expect(lsa.checksum).to eq(checksum)
      #    end
      #  end
      #end

      describe OSPFv3::DbDescription do
        describe '#parse' do
          it 'parses a real packet' do
            ospf = packets[2].ospfv3
            expect(ospf.type).to eq(2)
            expect(ospf.body).to be_a(OSPFv3::DbDescription)

            dbd = ospf.body
            expect(dbd.options).to eq(0x13)
            expect(dbd.mtu).to eq(1500)
            expect(dbd.flags).to eq(2)
            expect(dbd.seqnum).to eq(7494)
            expect(dbd.lsas.size).to eq(7)
            expect(dbd.lsas[0].age).to eq(39)
            expect(dbd.lsas[0].type).to eq(0x2001)
            expect(dbd.lsas[0].human_type).to eq('Router')
            expect(dbd.lsas[0].link_state_id).to eq('0.0.0.0')
            expect(dbd.lsas[0].advertising_router).to eq('1.1.1.1')
            expect(dbd.lsas[0].seqnum).to eq(0x80000002)
            expect(dbd.lsas[0].checksum).to eq(0xd13a)
            expect(dbd.lsas[0].length).to eq(24)

            expect(dbd.lsas[1].age).to eq(40)
            expect(dbd.lsas[1].human_type).to eq('Inter-Area-Prefix')
            expect(dbd.lsas[1].link_state_id).to eq('0.0.0.0')
            expect(dbd.lsas[1].advertising_router).to eq('1.1.1.1')
            expect(dbd.lsas[1].seqnum).to eq(0x80000001)
            expect(dbd.lsas[1].checksum).to eq(0x0ebd)
            expect(dbd.lsas[1].length).to eq(36)

            expect(dbd.lsas[6].age).to eq(34)
            expect(dbd.lsas[6].human_type).to eq('Intra-Area-Prefix')
            expect(dbd.lsas[6].link_state_id).to eq('0.0.0.0')
            expect(dbd.lsas[6].advertising_router).to eq('1.1.1.1')
            expect(dbd.lsas[6].seqnum).to eq(0x80000001)
            expect(dbd.lsas[6].checksum).to eq(0xe8d2)
            expect(dbd.lsas[6].length).to eq(44)
          end
        end
      end

      describe OSPFv3::LSRequest do
        describe '#parse' do
          it 'parses a real packet' do
            ospf = packets[3].ospfv3
            expect(ospf.type).to eq(3)
            expect(ospf.body).to be_a(OSPFv3::LSRequest)
            
            lsr = ospf.body
            expect(lsr.lsrs.size).to eq(6)
            expected = [{ type: 'Router',
                          link_state_id: '0.0.0.0',
                          advertising_router: '2.2.2.2'},
                          { type: 'Inter-Area-Prefix',
                            link_state_id: '0.0.0.3',
                            advertising_router: '2.2.2.2'},
                          { type: 'Inter-Area-Prefix',
                            link_state_id: '0.0.0.2',
                            advertising_router: '2.2.2.2'},
                          { type: 'Inter-Area-Prefix',
                            link_state_id: '0.0.0.1',
                            advertising_router: '2.2.2.2'},
                          { type: 'Inter-Area-Prefix',
                            link_state_id: '0.0.0.0',
                            advertising_router: '2.2.2.2'},
                          { type: 'Link',
                            link_state_id: '0.0.0.5',
                            advertising_router: '2.2.2.2'}]
            expect(lsr.lsrs.map(&:to_h)).to eq(expected)
          end
        end
      end
    end
  end
end
