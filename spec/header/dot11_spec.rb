require_relative '../spec_helper'

module PacketGen
  module Header
    describe Dot11 do
      let(:file) { File.join(__dir__, 'ieee802.11-join.pcapng') }

      context '#read' do
        it 'reads different kinds of Dot11 packets' do
          classes = [Dot11::Beacon, Dot11::ProbeReq, Dot11::ProbeReq, Dot11::ProbeResp,
                     Dot11::Control, Dot11::Beacon, Dot11::Auth, Dot11::Control,
                     Dot11::Auth, Dot11::Control, Dot11::AssoReq, Dot11::Control,
                     Dot11::AssoResp, Dot11::Control]
          pkts = Packet.read(file)
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
      end
    end
  end
end
