require_relative '../spec_helper'

module PacketGen
  module Header
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
          expect(dot11.fields.size).to eq(10)
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
            ht_ctrl: 0x8000_1234
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
          pkts = Packet.read(ctrl_mngt_file)
          expect(pkts.map { |pkt| pkt.headers.last.class }).to eq(classes)

          expect(pkts[0].beacon.timestamp).to eq(0x26bbb9189)
          expect(pkts[0].beacon.elements.first.human_type).to eq('SSID')
          expect(pkts[0].beacon.elements.first.value).to eq('martinet3')
          expect(pkts[1].probereq.elements[1].human_type).to eq('Rates')
          expect(pkts[1].probereq.elements[1].value).
            to eq(PacketGen.force_binary "\x82\x84\x8b\x96\x0c\x12\x18\x24")
          expect(pkts[3].proberesp.timestamp).to eq(0x26bbcad38)
          expect(pkts[3].proberesp.beacon_interval).to eq(0x64)
          expect(pkts[3].proberesp.cap).to eq(0x0411)
          expect(pkts[3].proberesp.elements[2].human_type).to eq('DSset')
          expect(pkts[3].proberesp.elements[2].value).to eq("\x0b")
          expect(pkts[4].dot11.human_type).to eq('Control')
          expect(pkts[4].dot11.human_subtype).to eq('Ack')
          expect(pkts[5].is? 'Beacon').to be(true)
          expect(pkts[5].is? 'Dot11::Beacon').to be(true)
          expect(pkts[6].is? 'Dot11::Auth').to be(true)
          expect(pkts[6].auth.algo).to eq(0)
          expect(pkts[6].auth.seqnum).to eq(1)
          expect(pkts[6].auth.status).to eq(0)
          expect(pkts[6].auth.elements.size).to eq(0)
          expect(pkts[8].is? 'Dot11::Auth').to be(true)
          expect(pkts[8].auth.seqnum).to eq(2)
          expect(pkts[8].auth.elements.size).to eq(1)
          expect(pkts[10].is? 'Dot11::AssoReq').to be(true)
          expect(pkts[10].assoreq.cap).to eq(0x411)
          expect(pkts[10].assoreq.listen_interval).to eq(10)
          expect(pkts[10].assoreq.elements.size).to eq(4)
          expect(pkts[10].assoreq.elements[2].human_type).to eq('ESRates')
          expect(pkts[12].is? 'Dot11::AssoResp').to be(true)
          expect(pkts[12].assoresp.cap).to eq(0x411)
          expect(pkts[12].assoresp.status).to eq(0)
          expect(pkts[12].assoresp.aid).to eq(0xc004)
          expect(pkts[12].assoresp.elements.size).to eq(3)
        end

        it 'reads key packets' do
          pkt = Packet.read(wap_file)[27]
          expect(pkt.headers.map(&:class)).to eq([RadioTap, Dot11::Data, LLC, SNAP, Dot1x])
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
          expect(pkt.body.size).to eq(356)
        end

        it 'reads clear data packets' do
          pkt = Packet.read(data_file).first
          expect(pkt.headers.map(&:class)).to eq([PPI, Dot11::Data, LLC, SNAP,
                                                  IP, UDP, DNS])
          expect(pkt.snap.proto_id).to eq(0x800)
          expect(pkt.dns.qd.first.to_human).to eq('A IN www.polito.it.')
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
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
          a1 = pkt.to_s.unpack('C*').map { |v| "%02x" % v }
          a2 = data_str[0..-5].unpack('C*').map { |v| "%02x" % v }
          expect(pkt.to_s).to eq(data_str[0..-5]) # remove FCS
        end
      end

      describe '#inspect' do
        it 'returns a String with applicable attributes' do
          dot11 = Dot11.new
          str = dot11.inspect
          expect(str).to be_a(String)
          (dot11.to_h.keys - %i(body)).each do |attr|
            expect(str).to include(attr.to_s)
          end

          dot11 = Dot11::Control.new
          str = dot11.inspect
          expect(str).to be_a(String)
          expect(dot11.to_h.keys).to_not include(:mac3, :sequence_ctrl, :mac4,
                                                 :qos_ctrl, :ht_ctrl)
          (dot11.to_h.keys - %i(body)).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe '#to_w' do
        it 'responds to #to_w'
        it 'sends a Dot11 packet on "wire"'
      end
    end
  end
end
