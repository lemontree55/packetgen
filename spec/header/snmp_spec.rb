# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module Header
    describe SNMP do
      let(:ber) { read_raw_packets('snmp.pcapng') }

      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(SNMP).with(sport: 161)
          expect(UDP).to know_header(SNMP).with(dport: 161)
          expect(UDP).to know_header(SNMP).with(sport: 162)
          expect(UDP).to know_header(SNMP).with(dport: 162)
        end

        it 'accepts to be added in UDP packets' do
          pkt = PacketGen.gen('UDP')
          expect { pkt.add('SNMP') }.not_to raise_error
          expect(pkt.udp.dport).to eq(161)
        end
      end

      describe '#initialize' do
        it 'creates a SNMP header with default values' do
          snmp = SNMP.new
          expect(snmp.version).to eq('v2c')
          expect(snmp.community).to eq('public')
          expect(snmp.data).to be_a(SNMP::PDUs)
        end

        it 'accepts options' do
          options = {
            version: 3,
            community: 'community'
          }
          snmp = SNMP.new(options)
          expect(snmp.version).to eq('v3')
          expect(snmp.community).to eq('community')
          expect(snmp.pdu).to be_nil
        end

        it 'accepts a PDU' do
          snmp = SNMP.new(chosen_pdu: SNMP::PDU_GET,
                          pdu: { id: 1, varbindlist: [{ name: '1.2.3.4' }] })
          expect(snmp.pdu).to be_a(SNMP::GetRequest)

          pdu = snmp.pdu
          expect(pdu[:id].value).to eq(1)
          expect(pdu[:varbindlist].size).to eq(1)
          expect(pdu[:varbindlist][0]).to be_a(SNMP::VarBind)
          expect(pdu[:varbindlist][0][:name].value).to eq('1.2.3.4')
          expect(pdu[:varbindlist][0][:value]).to be_a(RASN1::Types::Any)
          expect(pdu[:varbindlist][0][:value].value).to be_nil
        end
      end

      describe '#read' do
        let(:snmp) { SNMP.new }

        it 'reads a getRequest from a string' do
          snmp.read ber[0][42..]
          expect(snmp.version).to eq('v1')
          expect(snmp.community).to eq('public')
          expect(snmp.data.root.chosen).to eq(SNMP::PDU_GET)
        end

        it 'reads a getResponse from a string' do
          snmp.read ber[1][42..]
          expect(snmp.version).to eq('v1')
          expect(snmp.community).to eq('public')
          expect(snmp.data.root.chosen).to eq(SNMP::PDU_RESPONSE)
          expect(snmp.data.chosen_value[:id].value).to eq(39)
          expect(snmp.pdu[:id].value).to eq(39)
          list = snmp.pdu[:varbindlist]

          os1 = RASN1::Types::OctetString.new(value: 'B6300')
          os2 = RASN1::Types::OctetString.new(value: "Chandra's cube")
          expected_list = [SNMP::VarBind.new(name: '1.3.6.1.2.1.1.5.0',
                                             value: os1.to_der),
                           SNMP::VarBind.new(name: '1.3.6.1.2.1.1.6.0',
                                             value: os2.to_der)]
          expect(list.value).to eq(expected_list)
        end

        it 'parses a complete packet' do
          snmp = Packet.parse(ber[1])
          expect(snmp.is?('IP')).to be(true)
          expect(snmp.is?('UDP')).to be(true)
          expect(snmp.is?('SNMP')).to be(true)
          expect(snmp.snmp.data.root.chosen).to eq(SNMP::PDU_RESPONSE)
        end
      end

      describe '#to_s' do
        it 'returns a binary string' do
          snmp = SNMP.new(version: 'v1')
          snmp.data.chosen = 0
          snmp.pdu[:id] = 39
          snmp.pdu[:error] = 'no_error'
          snmp.pdu[:error_index] = 0
          varlist = snmp.data.chosen_value[:varbindlist]
          varlist << { name: '1.3.6.1.2.1.1.5.0',
                       value: RASN1::Types::Null.new }
          varlist << { name: '1.3.6.1.2.1.1.6.0',
                       value: RASN1::Types::Null.new }
          expect(snmp.to_s).to eq(ber[0][42..])
        end
      end

      describe '#inspect' do
        it 'returns a String with all attributes' do
          snmp = SNMP.new
          str = snmp.inspect
          %w[version community data].each do |attr|
            expect(str).to include(attr)
          end
          expect(str).not_to include('ASN.1 content')
        end

        it 'returns a String with PDU data' do
          snmp = SNMP.new(chosen_pdu: SNMP::PDU_GET,
                          pdu: { id: 1, varbindlist: [{ name: '1.2.3.4' }] })
          str = snmp.inspect
          expect(str).to include('ASN.1 content')
          %w[id error error_index bindings varbind name value].each do |field|
            expect(str).to include(field)
          end
        end
      end

      describe SNMP::PDUs do
        it 'index of a model in CHOICE corresponds to its PDU number' do
          pdus = SNMP::PDUs.new

          (0..8).each do |i|
            expect(pdus.value[i].id).to eq(i)
          end
        end
      end
    end
  end
end
