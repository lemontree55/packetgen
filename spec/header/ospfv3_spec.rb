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

      describe OSPFv3::IPv6Prefix do
        describe '#from_human' do
          it 'populates prefix from a string' do
            prefix = OSPFv3::IPv6Prefix.new
            prefix.from_human('2ac0:1::/60')
            expect(prefix.length).to eq(60)
            expect(prefix.options).to eq(0)
            expect(prefix.prefix.map(&:to_i)).to eq([0x2ac0_0001, 0])

            prefix.from_human('2ac0:1::')
            expect(prefix.length).to eq(128)
            expect(prefix.prefix.map(&:to_i)).to eq([0x2ac0_0001] + [0] * 3)
          end
        end
      end

      describe OSPFv3::LSAHeader do
        let(:lsa) { packets[5].ospfv3_lsupdate.lsas.first }

        describe '#calc_checksum' do
          it 'calculates Fletcher-16 checksum' do
            checksum = lsa.checksum
            lsa.checksum = 0xffff
            lsa.calc_checksum
            expect(lsa.checksum).to eq(checksum)
          end
        end

        describe '#calc_length' do
          it 'calculates LSA length' do
            lsa = OSPFv3::LSARouter.new
            lsa.calc_length
            expect(lsa.length).to eq(24)
          end
        end

        describe '#to_human' do
          it 'gives a human-readable string' do
            expect(lsa.to_human).to eq('LSA<Link,0.0.0.5,2.2.2.2>')
          end
        end

        describe '#to_lsa_header' do
          it 'returns only header of a given LSA' do
            lsah = lsa.to_lsa_header
            expect(lsah).to be_a(OSPFv3::LSAHeader)
            lsa_hash = lsa.to_h
            lsa_hash.delete(:body)
            expect(lsah.to_h).to eq(lsa_hash)
          end
        end
      end

      describe OSPFv3::ArrayOfLSA do
        describe '#push' do
          let(:ary) { OSPFv3::ArrayOfLSA.new }

          it 'adds correct LSA class' do
            ary << { type: 'Router' }
            ary << { type: 'Network' }
            ary << { type: 'Intra-Area-Prefix' }
            ary << { type: 0x8008 }
            result = ary.map(&:class)
            expect(result).to eq([OSPFv3::LSARouter, OSPFv3::LSANetwork,
                                  OSPFv3::LSAIntraAreaPrefix, OSPFv3::LSA])
          end

          it 'only adds headers when array was created with only_headers option' do
            ary = OSPFv3::ArrayOfLSA.new(only_headers: true)
            ary << { type: 'Router' }
            ary << { type: 'Network' }
            result = ary.map(&:class)
            expect(result).to eq([OSPFv3::LSAHeader] * 2)
          end

          it 'raises if no type was given' do
            expect { ary << {} }.to raise_error(ArgumentError)
          end
        end
      end

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
            expect(lsr.lsrs[0].to_human).to eq('LSR<Router,0.0.0.0,2.2.2.2>')
          end
        end
      end

      describe OSPFv3::LSUpdate do
        before(:each) do
          @lsup = OSPFv3::LSUpdate.new
          @lsup.lsas << { type: 'Router', age: 36, link_state_id: '0.0.0.1',
                          advertising_router: '1.1.1.1', sequence_number: 1 }
          @lsup.lsas << { type: 'Network', age: 36, link_state_id: '0.0.0.1',
                          advertising_router: '1.1.1.1', sequence_number: 1 }
        end

        describe '#calc_checksum' do
          it 'calculates checksum of all LSAs' do
            expect(@lsup.lsas_count).to eq(2)

            @lsup.calc_checksum
            expect(@lsup.lsas[0].checksum).to_not eq(0)
            expect(@lsup.lsas[1].checksum).to_not eq(0)
          end
        end

        describe '#calc_length' do
          it 'calculates length of all LSAs' do
            @lsup.lsas[0].links << { type: 1, metric: 10, interface_id: 1,
                                     neighbor_interface_id: 1,
                                     neighbor_router_id: '1.1.1.1' }
            @lsup.calc_length
            expect(@lsup.lsas[0].length).to eq(40)
            expect(@lsup.lsas[1].length).to eq(24)
          end
        end

        describe '#parse' do
          let(:ospf) { packets[4].ospfv3 }

          it 'parses a real packet with a Router LSA' do
            expect(ospf.type).to eq(4)
            expect(ospf.body).to be_a(OSPFv3::LSUpdate)

            lsu = ospf.body
            expect(lsu.lsas_count).to eq(4)
            expect(lsu.lsas.size).to eq(4)
            lsa = lsu.lsas.last
            expect(lsa.human_type).to eq('Router')
            expect(lsa.flags).to eq(1)
            expect(lsa.nt_flag?).to eq(false)
            expect(lsa.v_flag?).to eq(false)
            expect(lsa.e_flag?).to eq(false)
            expect(lsa.b_flag?).to eq(true)
            expect(lsa.options).to eq(0x33)
            expect(lsa.dc_opt?).to eq(true)
            expect(lsa.r_opt?).to eq(true)
            expect(lsa.n_opt?).to eq(false)
            expect(lsa.x_opt?).to eq(false)
            expect(lsa.e_opt?).to eq(true)
            expect(lsa.v6_opt?).to eq(true)
            expect(lsa.links.size).to eq(1)
            expect(lsa.links[0].to_human).to eq('Link<type:2,metric:10,id:5,neighbor_id:5,neighbor_router:1.1.1.1>')
          end

          it 'parses a real packet with a Network LSA' do
            lsu = ospf.body
            lsa = lsu.lsas.first
            expect(lsa.human_type).to eq('Network')
            expect(lsa.reserved).to eq(0)
            expect(lsa.options).to eq(0x33)
            expect(lsa.routers.size).to eq(2)
            expect(lsa.routers[0].to_human).to eq('1.1.1.1')
            expect(lsa.routers[1].to_human).to eq('2.2.2.2')
          end

          it 'parses a real packet with a Intra-Area-Prefix LSA' do
            lsu = ospf.body
            lsa = lsu.lsas[1]
            expect(lsa.human_type).to eq('Intra-Area-Prefix')
            expect(lsa.prefix_count).to eq(1)
            expect(lsa.prefixes.size).to eq(1)
            expect(lsa.ref_ls_type).to eq(0x2002)
            expect(lsa.ref_link_state_id).to eq('0.0.0.5')
            expect(lsa.ref_advertising_router).to eq('1.1.1.1')
            expect(lsa.prefixes.first.length).to eq(64)
            expect(lsa.prefixes.first.options).to eq(0)
            expect(lsa.prefixes.first.reserved).to eq(0)
            prefix = lsa.prefixes.first.prefix.map(&:to_i)
            expect(prefix).to eq([0x20010db8, 0x12])
            expect(lsa.prefixes.first.to_human).to eq('2001:db8:0:12::/64')
          end
        end
      end
    end
  end
end
