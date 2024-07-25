require_relative '../spec_helper'
require_relative '../shared_examples_for_headerable'

$global_var = false

module PacketGen
  module Header
    describe ASN1Base do

      class TestBase2 < Base
        define_attr :field1, BinStruct::Int8
        define_attr :field2, BinStruct::Int8
      end

      class ASN1ToBind < ASN1Base
        boolean(:bool)

        def added_to_packet(packet)
          $global_var = true
        end
      end

      context '.bind' do
        after(:each) { clear_bindings TestBase2 }

        it 'binds a ASN1 header to another header with a single value' do
          TestBase2.bind ASN1ToBind, field1: 55
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 55)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(0)
        end

        it 'binds a ASN1 header to another header with multiple field' do
          TestBase2.bind ASN1ToBind, field1: 55, field2: 2
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 55, field2: 2)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(2)
        end

        it 'binds a ASN1 header to another header using a lambda' do
          TestBase2.bind ASN1ToBind, field1: ->(v) { v.nil? ? 128 : v > 127 }
          expect(TestBase2).to_not know_header(ASN1ToBind).with(field1: 127)
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 128)
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 129)
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 255)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(128)
        end

        it 'binds a header with multiple possibility (multiple calls to .bind)' do
          TestBase2.bind ASN1ToBind, field1: 55, field2: 2
          TestBase2.bind ASN1ToBind, field1: 54, field2: 3
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 55, field2: 2)
          expect(TestBase2).to know_header(ASN1ToBind).with(field1: 54, field2: 3)

          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(2)
        end
      end

      context 'adding header to a packet' do
        it 'calls #added_to_packet' do
          $global_var = false
          Packet.gen('ASN1ToBind')
          expect($global_var).to be(true)
        end
      end

      # Use of a real class, as ASN1Base cannot be instanciated
      include_examples 'headerable', ASN1ToBind
    end
  end
end
