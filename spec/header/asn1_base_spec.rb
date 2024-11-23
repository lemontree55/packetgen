# frozen_string_literal: true

require_relative '../spec_helper'
require_relative '../shared_examples_for_headerable'

module PacketGenAsn1BaseTests
  class TestBase2 < PacketGen::Header::Base
    define_attr :field1, BinStruct::Int8
    define_attr :field2, BinStruct::Int8
  end

  class ASN1ToBind < PacketGen::Header::ASN1Base
    boolean(:bool)

    def added_to_packet(packet)
      packet.instance_eval('@added = true')
    end
  end
end

module PacketGen
  module Header
    describe ASN1Base do
      before(:all) do
        PacketGen::Header.add_class(PacketGenAsn1BaseTests::TestBase2)
        PacketGen::Header.add_class(PacketGenAsn1BaseTests::ASN1ToBind)
      end

      after(:all) do
        PacketGen::Header.remove_class(PacketGenAsn1BaseTests::TestBase2)
        PacketGen::Header.remove_class(PacketGenAsn1BaseTests::ASN1ToBind)
      end

      describe '.bind' do
        after { clear_bindings(PacketGenAsn1BaseTests::TestBase2) }

        it 'binds a ASN1 header to another header with a single value' do
          PacketGenAsn1BaseTests::TestBase2.bind(PacketGenAsn1BaseTests::ASN1ToBind, field1: 55)
          expect(PacketGenAsn1BaseTests::TestBase2).to know_header(PacketGenAsn1BaseTests::ASN1ToBind).with(field1: 55)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(0)
        end

        it 'binds a ASN1 header to another header with multiple field' do
          PacketGenAsn1BaseTests::TestBase2.bind(PacketGenAsn1BaseTests::ASN1ToBind, field1: 55, field2: 2)
          expect(PacketGenAsn1BaseTests::TestBase2).to know_header(PacketGenAsn1BaseTests::ASN1ToBind).with(field1: 55, field2: 2)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(2)
        end

        it 'binds a ASN1 header to another header using a lambda' do
          PacketGenAsn1BaseTests::TestBase2.bind(PacketGenAsn1BaseTests::ASN1ToBind, field1: ->(v) { v.nil? ? 128 : v > 127 })
          expect(PacketGenAsn1BaseTests::TestBase2).not_to know_header(PacketGenAsn1BaseTests::ASN1ToBind).with(field1: 127)
          expect(PacketGenAsn1BaseTests::TestBase2).to know_header(PacketGenAsn1BaseTests::ASN1ToBind).with(field1: 128)
          expect(PacketGenAsn1BaseTests::TestBase2).to know_header(PacketGenAsn1BaseTests::ASN1ToBind).with(field1: 129)
          expect(PacketGenAsn1BaseTests::TestBase2).to know_header(PacketGenAsn1BaseTests::ASN1ToBind).with(field1: 255)
          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(128)
        end

        it 'binds a header with multiple possibility (multiple calls to .bind)' do
          PacketGenAsn1BaseTests::TestBase2.bind(PacketGenAsn1BaseTests::ASN1ToBind, field1: 55, field2: 2)
          PacketGenAsn1BaseTests::TestBase2.bind(PacketGenAsn1BaseTests::ASN1ToBind, field1: 54, field2: 3)
          expect(PacketGenAsn1BaseTests::TestBase2).to know_header(PacketGenAsn1BaseTests::ASN1ToBind).with(field1: 55, field2: 2)
          expect(PacketGenAsn1BaseTests::TestBase2).to know_header(PacketGenAsn1BaseTests::ASN1ToBind).with(field1: 54, field2: 3)

          pkt = Packet.new.add('TestBase2').add('ASN1ToBind')
          expect(pkt.testbase2.field1).to eq(55)
          expect(pkt.testbase2.field2).to eq(2)
        end
      end

      context 'when adding header to a packet' do
        it 'calls #added_to_packet' do
          p = Packet.gen('ASN1ToBind')
          expect(p.instance_eval('@added')).to be(true)
        end
      end

      # Use of a real class, as ASN1Base cannot be instanciated
      include_examples 'headerable', PacketGenAsn1BaseTests::ASN1ToBind
    end
  end
end
