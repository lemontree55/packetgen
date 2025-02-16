# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module Header
    describe EAP do
      describe 'binding' do
        it 'in Dot1x packets' do
          expect(Dot1x).to know_header(EAP).with(type: 0)
        end

        it 'accepts to be added in Dot1x packets' do
          pkt = PacketGen.gen('Dot1x')
          expect { pkt.add('EAP') }.not_to raise_error
          expect(pkt.dot1x.type).to eq(0)
        end
      end

      describe '#initialize' do
        it 'creates a EAP header with default values' do
          eap = EAP.new
          expect(eap).to be_a(EAP)
          expect(eap.code).to eq(1)
          expect(eap.id).to eq(0)
          expect(eap.length).to eq(5)
          expect(eap.present?(:type)).to be(true)
          expect(eap.type).to eq(1)
          expect(eap.body).to eq('')
        end

        it 'accepts options' do
          options = {
            code: 0xf5,
            id: 0x81,
            length: 1000,
            body: 'this is a body'
          }
          eap = EAP.new(options)
          options.each do |key, value|
            expect(eap.send(key)).to eq(value)
          end
        end

        %w[Success Failure].each do |code|
          it "does not generate a type field for #{code} code" do
            eap = EAP.new(code: code)
            expect(eap.present?(:type)).to be(false)
          end
        end
      end

      describe '#read' do
        let(:eap) { EAP.new }

        it 'sets header from a string' do
          str = (1..eap.sz).to_a.pack('C*') + 'body'
          eap.read str
          expect(eap.code).to eq(1)
          expect(eap.id).to eq(2)
          expect(eap.length).to eq(0x0304)
          expect(eap.type).to eq(5)
          expect(eap.body).to eq('body')

          str = (3..(EAP.new.sz + 2)).to_a.pack('C*') + 'body'
          eap.read str
          expect(eap.code).to eq(3)
          expect(eap.id).to eq(4)
          expect(eap.length).to eq(0x0506)
          expect(eap.body).to eq("\x07body")
        end

        it 'decodes a complex string' do
          Dot11.fcs = false
          file = File.join(__dir__, 'wps.pcapng')
          raws = PcapNG::File.new.read_packet_bytes(file)

          pkt = Packet.parse(raws[2])
          expect(pkt.is?('Dot11::Data')).to be(true)
          expect(pkt.is?('Dot1x')).to be(true)
          expect(pkt.is?('EAP')).to be(true)
          expect(pkt.eap).to be_a_response
          expect(pkt.eap.code).to eq(2)
          expect(pkt.eap.human_code).to eq('Response')
          expect(pkt.eap.id).to eq(13)
          expect(pkt.eap.type).to eq(1)
          expect(pkt.eap.human_type).to eq('Identity')
          expect(pkt.body).to eq('WFA-SimpleConfig-Enrollee-1-0')

          pkt = Packet.parse(raws[3])
          expect(pkt.is?('EAP')).to be(true)
          expect(pkt.eap).to be_a_request
          expect(pkt.eap.code).to eq(1)
          expect(pkt.eap.human_code).to eq('Request')
          expect(pkt.eap.id).to eq(14)
          expect(pkt.eap.type).to eq(254)
          expect(pkt.eap.human_type).to eq('Expanded Types')
          expect(pkt.eap.vendor_id).to eq(0x372a)
          expect(pkt.eap.vendor_type).to eq(1)
          expect(pkt.body).to eq("\x01\x00".b)

          pkt = Packet.parse(raws.last)
          expect(pkt.is?('EAP')).to be(true)
          expect(pkt.eap).to be_a_failure
          expect(pkt.eap).not_to be_a_success
          expect(pkt.eap.human_code).to eq('Failure')
          expect(pkt.eap.id).to eq(18)
        end
      end

      describe '#to_s' do
        it 'returns a binary string without type field' do
          eap = EAP.new(code: 'Success')
          expect(eap.to_s).to eq("\x03\x00\x00\x04".b)
        end

        it 'returns a binary string with type field' do
          eap = EAP.new(code: 'Request', type: 46)
          expect(eap.to_s).to eq("\x01\x00\x00\x05\x2e".b)
        end

        it 'returns a binary string with type and vendor fields' do
          eap = EAP.new(code: 'Request', type: 254)
          expect(eap.to_s).to eq("\x01\x00\x00\x0c\xfe\x00\x00\x00\x00\x00\x00\x00".b)
        end
      end

      describe '#inspect' do
        it 'returns a string without type field' do
          eap = EAP.new(code: 'Success')
          str = eap.inspect
          %i[code id length].each do |attr|
            expect(str).to include(attr.to_s)
          end
          %i[type vendor_id vendor_type].each do |attr|
            expect(str).not_to include(attr.to_s)
          end
        end

        it 'returns a string with type field' do
          eap = EAP.new(code: 'Request', type: 46)
          str = eap.inspect
          %i[code id length type].each do |attr|
            expect(str).to include(attr.to_s)
          end
          %i[vendor_id vendor_type].each do |attr|
            expect(str).not_to include(attr.to_s)
          end
        end

        it 'returns a string with type and vendor fields' do
          eap = EAP.new(code: 'Request', type: 254)
          str = eap.inspect
          (eap.attributes - %i[body]).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe '#reply!' do
        it 'inverts between requests and responses' do
          eap = EAP.new
          eap.reply!
          expect(eap.code).to eq(2)
          eap.reply!
          expect(eap.code).to eq(1)
        end

        it 'does nothing on success and failure packets' do
          eap = EAP.new(code: 'Success')
          eap.reply!
          expect(eap.code).to eq(3)
          eap = EAP.new(code: 'Failure')
          eap.reply!
          expect(eap.code).to eq(4)
        end
      end

      describe EAP::MD5 do
        describe '#initialize' do
          it 'creates a EAP::MD5 header with default values' do
            eap = EAP::MD5.new
            expect(eap.type?).to be(true)
            expect(eap.type).to eq(EAP::TYPES['MD5-Challenge'])
          end
        end
      end

      describe EAP::TLS do
        describe '#initialize' do
          it 'creates a EAP::TLS header with default values' do
            eap = EAP::TLS.new
            expect(eap.type?).to be(true)
            expect(eap.type).to eq(EAP::TYPES['EAP-TLS'])
          end
        end

        describe '#read' do
          before(:all) { @packets = read_packets('dot1x.pcapng') }

          it 'decodes complex strings' do
            pkt = @packets[3]
            expect(pkt.is?('EAP')).to be(true)
            expect(pkt.eap).to be_a_request
            expect(pkt.eap.human_type).to eq('EAP-TLS')
            expect(pkt.eap_tls.flags).to eq(0x20)
            expect(pkt.eap_tls).not_to be_length_present
            expect(pkt.eap_tls).not_to be_more_fragments
            expect(pkt.eap_tls).to be_tls_start

            pkt = @packets[4]
            expect(pkt.is?('EAP::TLS')).to be(true)
            expect(pkt.eap).to be_a_response
            expect(pkt.eap.human_type).to eq('EAP-TLS')
            expect(pkt.eap_tls.flags).to eq(0)
            expect(pkt.body.sz).to eq(pkt.eap.length - 6)
          end
        end

        describe '#inspect' do
          let(:eaptls) { EAP::TLS.new }

          it 'only prints present fields' do
            str = eaptls.inspect
            expect(str).not_to include('tls_length')

            eaptls2 = EAP::TLS.new(l: true)
            str = eaptls2.inspect
            expect(str).to include('tls_length')
          end

          it 'formats flags field as flags' do
            str = eaptls.inspect
            expect(str).to include('flags: ...')
          end
        end
      end

      describe EAP::TTLS do
        let(:eapttls) { EAP::TTLS.new }

        describe '#initialize' do
          it 'creates a EAP::TTLS header with default values' do
            expect(eapttls.type?).to be(true)
            expect(eapttls.type).to eq(EAP::TYPES['EAP-TTLS'])
          end
        end

        describe '#inspect' do
          it 'formats flags field as flags' do
            str = eapttls.inspect
            expect(str).to include('flags: ...')
            expect(str).to include('version: 0')
          end
        end
      end

      describe EAP::FAST do
        describe '#initialize' do
          it 'creates a EAP::FAST header with default values' do
            eap = EAP::FAST.new
            expect(eap.type?).to be(true)
            expect(eap.type).to eq(EAP::TYPES['EAP-FAST'])
          end
        end
      end
    end
  end
end
