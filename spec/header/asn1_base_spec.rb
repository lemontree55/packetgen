require_relative '../spec_helper'

$global_var = false

module PacketGen
  module Header
    describe ASN1Base do

      class TestBase2 < Base
        define_field :field1, Types::Int8
        define_field :field2, Types::Int8
      end

      class ASN1ToBind < ASN1Base
        boolean(:bool)

        def added_to_packet(packet)
          $global_var = true
        end
      end

      context '.bind_header' do
        after(:each) { clear_bindings TestBase2 }

        it 'binds a ASN1 header to another header with a single value' do
          TestBase2.bind_header ASN1ToBind, field1: 55
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 55)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(0)
        end

        it 'binds a header to another one with multiple field (or case)' do
          TestBase2.bind_header ASN1ToBind, field1: 55, field2: 1
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 55, field2: 1)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(1)
        end

        it 'binds a header to another one with multiple field (and case)' do
          TestBase2.bind_header ASN1ToBind, op: :and, field1: 55, field2: 2
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 55, field2: 2)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(2)
        end

        it 'binds a header to another one using a lambda' do
          TestBase2.bind_header ASN1ToBind, field1: ->(v) { v.nil? ? 128 : v > 127 }
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(128)
        end
      end
      
      context 'adding header to a packet' do
        it 'calls #added_to_packet' do
          $global_var = false
          Packet.gen('ASN1ToBind')
          expect($global_var).to be(true)
        end
      end
    end
  end
end
