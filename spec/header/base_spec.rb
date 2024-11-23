# frozen_string_literal: true

require_relative '../spec_helper'
require_relative '../shared_examples_for_headerable'

module PGTest
  class Base < PacketGen::Header::Base
    define_attr :field1, BinStruct::Int8
    define_attr :field2, BinStruct::Int8
    define_attr :body, BinStruct::String
  end
  PacketGen::Header.add_class Base

  class ToBind < PacketGen::Header::Base
    define_attr :field, BinStruct::Int32, default: 1
    define_attr :str, BinStruct::String
    def added_to_packet(packet)
      packet.instance_eval('@tobind_added = true')
    end

    # used to check behaviour on Packet#is?, and on magic header method.
    def protocol_name
      self.class.to_s
    end
  end
  PacketGen::Header.add_class ToBind
end

module PacketGenBaseTests
  class PacketTest < PacketGen::Header::Base
    define_attr :field, BinStruct::Int8, default: ->(h) { h.packet ? h.packet.ip.tos : 255 }
  end

  class PacketTest2 < PacketGen::Header::Base
    define_attr :field, BinStruct::Int8, builder: lambda { |h, _|
      lt = h.packet && (h.packet.ip.tos > 0) ? BinStruct::Int16 : BinStruct::Int8
      lt.new
    }
  end
end

module PacketGen
  module Header
    describe Base do
      describe '.bind' do
        after { clear_bindings PGTest::Base }

        it 'binds a header with a single value' do
          PGTest::Base.bind PGTest::ToBind, field1: 55
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 55)
          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt).to respond_to(:base)
          expect(pkt).to respond_to(:pgtest_tobind)
          expect(pkt.base.field1).to eq(55)
          expect(pkt.base.field2).to eq(0)
          expect(pkt.pgtest_tobind.field).to eq(1)
        end

        it 'binds a header with multiple fields' do
          PGTest::Base.bind PGTest::ToBind, field1: 55, field2: 2
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 55, field2: 2)
          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt).to respond_to(:base)
          expect(pkt).to respond_to(:pgtest_tobind)
          expect(pkt.base.field1).to eq(55)
          expect(pkt.base.field2).to eq(2)
          expect(pkt.pgtest_tobind.field).to eq(1)
        end

        it 'binds a header using a lambda' do
          PGTest::Base.bind PGTest::ToBind, field1: ->(v) { v.nil? ? 128 : v > 127 }
          expect(PGTest::Base).not_to know_header(PGTest::ToBind).with(field1: 127)
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 128)
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 129)
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 255)
          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt).to respond_to(:base)
          expect(pkt).to respond_to(:pgtest_tobind)
          expect(pkt.base.field1).to eq(128)
          expect(pkt.pgtest_tobind.field).to eq(1)
        end

        it 'binds a header using procs' do
          PGTest::Base.bind PGTest::ToBind, procs: [->(h) { h.field1 = 42 },
                                                    ->(h) { h.field1 == 42 && BinStruct::Int32.new.read(h.body[0..3]).to_i > 0 }]
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 42, body: [1].pack('N'))

          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt).to respond_to(:base)
          expect(pkt).to respond_to(:pgtest_tobind)
          expect(pkt.base.field1).to eq(42)
          expect(pkt.pgtest_tobind.field).to eq(1)

          pkt2 = Packet.parse(pkt.to_s, first_header: 'PGTest::Base')
          expect(pkt2.is?('Base')).to be(true)
          expect(pkt2.is?('PGTest::ToBind')).to be(true)
          expect(pkt2.base.body).to be_a(PGTest::ToBind)

          pkt.pgtest_tobind.field = 0
          pkt3 = Packet.parse(pkt.to_s, first_header: 'PGTest::Base')
          expect(pkt3.is?('Base')).to be(true)
          expect(pkt3.is?('PGTest::ToBind')).to be(false)
          expect(pkt3.base[:body]).to be_a(BinStruct::String)
        end

        it 'binds a header with multiple possibility (multiple calls to .bind)' do
          PGTest::Base.bind PGTest::ToBind, field1: 55, field2: 2
          PGTest::Base.bind PGTest::ToBind, field1: 54, field2: 3
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 55, field2: 2)
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 54, field2: 3)

          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt.base.field1).to eq(55)
          expect(pkt.base.field2).to eq(2)
        end
      end

      context 'with a header from a plugin' do
        before(:all) { PGTest::Base.bind(PGTest::ToBind, field1: 55) }
        after(:all) { clear_bindings(PGTest::Base) }

        it 'Packet#add sets given fields' do
          pkt = PacketGen.gen('PGTest::Base').add('PGTest::ToBind', field: 42, str: '123')
          expect(pkt.pgtest_tobind.field).to eq(42)
          expect(pkt.pgtest_tobind.str).to eq('123')
        end
      end

      context 'when adding header to a packet' do
        before(:all) do
          Header.add_class(PacketGenBaseTests::PacketTest)
          IP.bind(PacketGenBaseTests::PacketTest, protocol: 255)
        end

        after(:all) { remove_binding(IP, PacketGenBaseTests::PacketTest) }

        it 'calls #added_to_packet' do
          p = Packet.gen('PGTest::ToBind')
          expect(p.instance_eval('@tobind_added')).to be(true)
        end

        it 'subclass may access to previous headers' do
          pkt = Packet.gen('IP', tos: 45).add('PacketTest')
          expect(pkt.packettest.field).to eq(45)
        end
      end

      context 'when parsing a packet' do
        before(:all) do
          Header.add_class(PacketGenBaseTests::PacketTest2)
          IP.bind(PacketGenBaseTests::PacketTest2, protocol: 255)
        end

        after(:all) { remove_binding(IP, PacketGenBaseTests::PacketTest) }

        it 'subclass may access to previous headers' do
          str = Packet.gen('IP', tos: 45).add('PacketTest2').to_s
          pkt = Packet.parse(str)
          expect(pkt.is?('IP')).to be(true)
          expect(pkt.is?('PacketTest2')).to be(true)
          expect(pkt.packettest2[:field]).to be_a(BinStruct::Int16)
        end
      end

      include_examples 'headerable', Base
    end
  end
end
