require_relative '../spec_helper'

module PacketGen
  module Header
    describe PPI do
      describe '#calc_length' do
        it 'computes PPI header length' do
          ppi = PPI.new
          ppi.calc_length
          expect(ppi.length).to eq(8)

          ppi.ppi_fields = '12345'
          ppi.calc_length
          expect(ppi.length).to eq(13)
        end
      end
    end

    describe RadioTap do
      describe '#calc_length' do
        it 'computes RadioTap header length' do
          rt = RadioTap.new
          rt.calc_length
          expect(rt.length).to eq(8)

          rt.radio_fields = '123456'
          rt.calc_length
          expect(rt.length).to eq(14)
        end
      end
    end

    describe Dot11 do
      let(:ctrl_mngt_file) { File.join(__dir__, 'ieee802.11-join.pcapng') }
      let(:wap_file) { File.join(__dir__, 'ieee802.11-data-wap.pcapng') }
      let(:data_file) { File.join(__dir__, 'ieee802.11-data.pcapng') }

      describe 'bindings' do
        it 'in PPI packets' do
          expect(PPI).to know_header(Dot11).with(dlt: 105)
        end
        it 'in RadioTap packets' do
          expect(RadioTap).to know_header(Dot11)
        end
      end

      it '.fcs? should default to true' do
        expect(Dot11.fcs?).to be(true)
      end

      describe '#initialize' do
        it 'creates a Dot11 header with default values' do
          dot11 = Dot11.new
          expect(dot11.frame_ctrl).to eq(0)
          expect(dot11.id).to eq(0)
          expect(dot11.mac1).to eq('00:00:00:00:00:00')
          expect(dot11.mac2).to eq('00:00:00:00:00:00')
          expect(dot11.mac3).to eq('00:00:00:00:00:00')
          expect(dot11.sequence_ctrl).to eq(0)
          expect(dot11.mac4).to eq('00:00:00:00:00:00')
          expect(dot11.qos_ctrl).to eq(0)
          expect(dot11.ht_ctrl).to eq(0)
          expect(dot11.fcs).to eq(0)
          expect(dot11.fields.size).to eq(11)
        end

        it 'accepts options' do
          options = {
            frame_ctrl: 0x0241,
            id: 0xffff,
            mac1: 'ff:ff:ff:ff:ff:ff',
            mac2: '01:02:03:04:05:06',
            mac3: '01:02:03:04:05:00',
            mac4: '01:02:03:00:01:02',
            sequence_ctrl: 0xcafe,
            qos_ctrl: 0xdeca,
            ht_ctrl: 0x8000_1234,
            fcs: 0x87654321
          }
          dot11 = Dot11.new(options)
          options.each do |key, value|
            expect(dot11.send(key)).to eq(value)
          end
        end
      end

      describe '#read' do
        it 'reads different kinds of Dot11 Mngt/Ctrl packets' do
          classes = [Dot11::Beacon, Dot11::ProbeReq, Dot11::ProbeReq, Dot11::ProbeResp,
                     Dot11::Control, Dot11::Beacon, Dot11::Auth, Dot11::Control,
                     Dot11::Auth, Dot11::Control, Dot11::AssoReq, Dot11::Control,
                     Dot11::AssoResp, Dot11::Control]
          Dot11.fcs = false
          pkts = Packet.read(ctrl_mngt_file)
          Dot11.fcs = true
          expect(pkts.map { |pkt| pkt.headers.last.class }).to eq(classes)

          expect(pkts[0].is? 'Dot11::Management').to be(true)
          expect(pkts[0].dot11_beacon.timestamp).to eq(0x26bbb9189)
          expect(pkts[0].dot11_beacon.elements.first.human_type).to eq('SSID')
          expect(pkts[0].dot11_beacon.elements.first.value).to eq('martinet3')
          expect(pkts[1].is? 'Dot11::Management').to be(true)
          expect(pkts[1].dot11_probereq.elements[1].human_type).to eq('Rates')
          expect(pkts[1].dot11_probereq.elements[1].value).
            to eq(force_binary "\x82\x84\x8b\x96\x0c\x12\x18\x24")
          expect(pkts[3].is? 'Dot11::Management').to be(true)
          expect(pkts[3].dot11_proberesp.timestamp).to eq(0x26bbcad38)
          expect(pkts[3].dot11_proberesp.beacon_interval).to eq(0x64)
          expect(pkts[3].dot11_proberesp.cap).to eq(0x0411)
          expect(pkts[3].dot11_proberesp.elements[2].human_type).to eq('DSset')
          expect(pkts[3].dot11_proberesp.elements[2].value).to eq("\x0b")
          expect(pkts[4].dot11.human_type).to eq('Control')
          expect(pkts[4].dot11.human_subtype).to eq('Ack')
          expect(pkts[5].is? 'Dot11::Beacon').to be(true)
          expect(pkts[6].is? 'Dot11::Management').to be(true)
          expect(pkts[6].is? 'Dot11::Auth').to be(true)
          expect(pkts[6].dot11_auth.algo).to eq(0)
          expect(pkts[6].dot11_auth.seqnum).to eq(1)
          expect(pkts[6].dot11_auth.status).to eq(0)
          expect(pkts[6].dot11_auth.elements.size).to eq(0)
          expect(pkts[8].is? 'Dot11::Auth').to be(true)
          expect(pkts[8].dot11_auth.seqnum).to eq(2)
          expect(pkts[8].dot11_auth.elements.size).to eq(1)
          expect(pkts[10].is? 'Dot11::AssoReq').to be(true)
          expect(pkts[10].dot11_assoreq.cap).to eq(0x411)
          expect(pkts[10].dot11_assoreq.listen_interval).to eq(10)
          expect(pkts[10].dot11_assoreq.elements.size).to eq(4)
          expect(pkts[10].dot11_assoreq.elements[2].human_type).to eq('ESRates')
          expect(pkts[12].is? 'Dot11::AssoResp').to be(true)
          expect(pkts[12].dot11_assoresp.cap).to eq(0x411)
          expect(pkts[12].dot11_assoresp.status).to eq(0)
          expect(pkts[12].dot11_assoresp.aid).to eq(0xc004)
          expect(pkts[12].dot11_assoresp.elements.size).to eq(3)
        end

        it 'reads key packets' do
          pkt = Packet.read(wap_file)[27]
          expect(pkt.headers.map(&:class)).to eq([RadioTap, Dot11::Data, LLC, SNAP, Dot1x])
          expect(pkt.dot11).to eq(pkt.dot11_data)
          expect(pkt.dot11.frame_ctrl).to eq(0x0802)
          expect(pkt.dot11.id).to eq(0x2c)
          expect(pkt.dot11.from_ds?).to be(true)
          expect(pkt.llc.dsap).to eq(170)
          expect(pkt.snap.proto_id).to eq(0x888e)
          expect(pkt.body[0, 8]).to eq([2, 0, 0x8a, 0, 16, 0, 0, 0].pack('C*'))
        end

        it 'reads encrypted data packets' do
          pkt = Packet.read(wap_file)[37]
          expect(pkt.headers.map(&:class)).to eq([RadioTap, Dot11::Data])
          expect(pkt.dot11.frame_ctrl).to eq(0x0841)
          expect(pkt.body.size).to eq(352)
          expect(pkt.dot11.fcs).to eq(0x2794a82c)
        end

        it 'reads clear data packets' do
          pkt = Packet.read(data_file).first
          expect(pkt.headers.map(&:class)).to eq([PPI, Dot11::Data, LLC, SNAP,
                                                  IP, UDP, DNS])
          expect(pkt.snap.proto_id).to eq(0x800)
          expect(pkt.dns.qd.first.to_human).to eq('A IN www.polito.it.')
        end
      end

      describe '#calc_checksum' do
        before(:each) { @pkt = PcapNG::File.new.read_packets(data_file)[0] }
        it 'calculates checksum' do
          expected_fcs = @pkt.dot11_data.fcs
          expect(@pkt.dot11_data.calc_checksum).to eq(expected_fcs)
        end

        it 'sets FCS field with calculated value' do
          expected_fcs = @pkt.dot11_data.fcs
          @pkt.dot11_data.fcs = 0
          @pkt.dot11_data.calc_checksum
          expect(@pkt.dot11_data.fcs).to eq(expected_fcs)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          Dot11.fcs = false
          begin
            mngt_ctrl = PcapNG::File.new.read_packet_bytes(ctrl_mngt_file)
            mngt_str = mngt_ctrl[0]
            ctrl_str = mngt_ctrl[4]
            wep_str = PcapNG::File.new.read_packet_bytes(wap_file)[37]
            data_str = PcapNG::File.new.read_packet_bytes(data_file).first

            pkt = Packet.parse(mngt_str)
            expect(pkt.is? 'Dot11::Beacon').to be(true)
            expect(pkt.to_s).to eq(mngt_str)

            pkt = Packet.parse(ctrl_str, first_header: 'Dot11')
            expect(pkt.is? 'Dot11::Control').to be(true)
            expect(pkt.to_s).to eq(ctrl_str)

            pkt = Packet.parse(wep_str, first_header: 'RadioTap')
            expect(pkt.is? 'Dot11::Data').to be(true)
            expect(pkt.dot11.wep?).to be(true)
            expect(pkt.to_s).to eq(wep_str)

            pkt = Packet.parse(data_str)
            expect(pkt.is? 'Dot11::Data').to be(true)
            expect(pkt.dot11.wep?).to be(false)
            expect(pkt.to_s).to eq(data_str[0..-5]) # remove FCS
          ensure
            Dot11.fcs = true
          end
        end
      end

      describe '#inspect' do
        it 'returns a String with applicable attributes' do
          dot11 = Dot11.new
          str = dot11.inspect
          expect(str).to be_a(String)
          (dot11.to_h.keys - %i[body]).each do |attr|
            expect(str).to include(attr.to_s)
          end

          dot11 = Dot11::Control.new
          str = dot11.inspect
          expect(str).to be_a(String)
          expect(dot11.to_h.keys).to_not include(:mac3, :sequence_ctrl, :mac4,
                                                 :qos_ctrl, :ht_ctrl)
          (dot11.to_h.keys - %i[body]).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe 'building a Dot11 packet' do
        it 'builds a Dot11::Beacon packet' do
          expect { PacketGen.gen('Beacon') }.to raise_error(ArgumentError, /^unknown/)
          pkt = nil
          expect { pkt = PacketGen.gen('Dot11::Management').add('Dot11::Beacon') }.to_not raise_error
          expect(pkt.headers.last).to be_a(Dot11::Beacon)

          expect(pkt.dot11).to eq(pkt.dot11_management)
          pkt.dot11.sequence_number = 12
          pkt.dot11.fragment_number = 1
          expect(pkt.dot11_management.sequence_ctrl).to eq(0xc1)

          expect do
            pkt.dot11_beacon.elements << { type: 'SSID', value: 'abcd' }
          end.to change { pkt.dot11_beacon.elements.size }.by(1)

          expect do
            pkt.dot11_management.add_element(type: 'vendor', value: 'Version 1.2')
          end.to change { pkt.dot11_beacon.elements.size }.by(1)

          pkt = PacketGen.gen('Dot11::Management')
          expect do
            pkt.dot11.add_element(type: 'vendor', value: 'Version 1.2')
          end.to raise_error(/add a Dot11::SubMngt/)
        end

        it 'builds a IP packet over IEEE 802.11 (no encryption)' do
          pkt = PacketGen.gen('Dot11::Data', mac1: '00:01:02:03:04:05',
                              mac2: '06:07:08:09:0a:0b', mac3: '0c:0d:0e:0f:10:11')
          expect { pkt.add('IP') }.to raise_error(ArgumentError, /no layer assoc/)

          pkt.add('LLC').add('SNAP').add('IP', src: '192.168.0.1', dst: '192.168.0.2')
          expect(pkt.dot11.wep?).to be(false)
          expect(pkt.dot11.type).to eq(2)
          expect(pkt.llc.dsap).to eq(0xaa)
          expect(pkt.llc.ssap).to eq(0xaa)
          expect(pkt.snap.oui).to eq('00:00:00')
          expect(pkt.snap.proto_id).to eq(0x800)
        end
      end
    end

    describe Dot11::Management do
      let(:ctrl_mngt_pkts) { read_packets('ieee802.11-join.pcapng') }
      describe '#reply!' do
        it 'inverts source and destination addresses' do
          pkt = ctrl_mngt_pkts[10]
          pkt.reply!
          expect(pkt.dot11.mac1).to eq('00:16:bc:3d:aa:57')
          expect(pkt.dot11.mac2).to eq('00:01:e3:41:bd:6e')
        end
      end
    end

    describe Dot11::Data do
      let(:data_pkts) { read_packets('ieee802.11-data.pcapng') }
      describe '#reply!' do
        it 'inverts SA and DA and DS flags (DS status is 01)' do
          pkt1, pkt2 = data_pkts[0..1]
          pkt1.reply!
          expect(pkt1.dot11.mac1).to eq(pkt2.dot11.mac1)
          expect(pkt1.dot11.mac2).to eq(pkt2.dot11.mac2)
          expect(pkt1.dot11.mac3).to eq(pkt2.dot11.mac3)
          expect(pkt1.dot11.from_ds?).to eq(pkt2.dot11.from_ds?)
          expect(pkt1.dot11.to_ds?).to eq(pkt2.dot11.to_ds?)
        end

        it 'inverts SA and DA and DS flags (DS status is 10)' do
          pkt1, pkt2 = data_pkts[0..1]
          pkt2.reply!
          expect(pkt2.dot11.mac1).to eq(pkt1.dot11.mac1)
          expect(pkt2.dot11.mac2).to eq(pkt1.dot11.mac2)
          expect(pkt2.dot11.mac3).to eq(pkt1.dot11.mac3)
          expect(pkt2.dot11.from_ds?).to eq(pkt1.dot11.from_ds?)
          expect(pkt2.dot11.to_ds?).to eq(pkt1.dot11.to_ds?)
        end
      end
    end
  end
end
