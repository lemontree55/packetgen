require_relative '../spec_helper'

$global_var = false

module PGTest
  class Base < PacketGen::Header::Base
    define_field :field1, PacketGen::Types::Int8
    define_field :field2, PacketGen::Types::Int8
    define_field :body, PacketGen::Types::String
  end
  PacketGen::Header.add_class Base

  class ToBind < PacketGen::Header::Base
    define_field :field, PacketGen::Types::Int32, default: 1
    define_field :str, PacketGen::Types::String
    def added_to_packet(_packet)
      $global_var = true
    end
    # used to check behaviour on Packet#is?, and on magic header method.
    def protocol_name
      self.class.to_s
    end
  end
  PacketGen::Header.add_class ToBind

end
module PacketGen
  module Header
    describe Base do
      describe '.bind_header' do
        after(:each) { clear_bindings PGTest::Base }

        it 'binds a header to another one with a single value' do
          PGTest::Base.bind_header PGTest::ToBind, field1: 55
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 55)
          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt).to respond_to(:base)
          expect(pkt).to respond_to(:pgtest_tobind)
          expect(pkt.base.field1).to eq(55)
          expect(pkt.base.field2).to eq(0)
          expect(pkt.pgtest_tobind.field).to eq(1)
        end

        it 'binds a header to another one with multiple field (or case)' do
          PGTest::Base.bind_header PGTest::ToBind, field1: 55, field2: 1
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 55, field2: 1)
          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt).to respond_to(:base)
          expect(pkt).to respond_to(:pgtest_tobind)
          expect(pkt.base.field1).to eq(55)
          expect(pkt.base.field2).to eq(1)
          expect(pkt.pgtest_tobind.field).to eq(1)
        end

        it 'binds a header to another one with multiple field (and case)' do
          PGTest::Base.bind_header PGTest::ToBind, op: :and, field1: 55, field2: 2
          expect(PGTest::Base).to know_header(PGTest::ToBind).with(field1: 55, field2: 2)
          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt).to respond_to(:base)
          expect(pkt).to respond_to(:pgtest_tobind)
          expect(pkt.base.field1).to eq(55)
          expect(pkt.base.field2).to eq(2)
          expect(pkt.pgtest_tobind.field).to eq(1)
        end

        it 'binds a header to another one using a lambda' do
          PGTest::Base.bind_header PGTest::ToBind, field1: ->(v) { v.nil? ? 128 : v > 127 }
          pkt = Packet.new.add('PGTest::Base').add('PGTest::ToBind')
          expect(pkt).to respond_to(:base)
          expect(pkt).to respond_to(:pgtest_tobind)
          expect(pkt.base.field1).to eq(128)
          expect(pkt.pgtest_tobind.field).to eq(1)
        end
      end

      describe '.bind' do
        after(:each) { clear_bindings PGTest::Base }

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
          expect(PGTest::Base).to_not know_header(PGTest::ToBind).with(field1: 127)
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
                                        ->(h) { h.field1 == 42 && Types::Int32.new.read(h.body[0..3]).to_i > 0 }]
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
          expect(pkt3.base.body).to be_a(Types::String)
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

      context 'in header plugin context' do
        before(:all) { PGTest::Base.bind PGTest::ToBind, field1: 55 }
        after(:all) { clear_bindings PGTest::Base }

        it 'Packet#add sets given fields' do
          pkt = PacketGen.gen('PGTest::Base').add('PGTest::ToBind', field: 42, str: '123')
          expect(pkt.pgtest_tobind.field).to eq(42)
          expect(pkt.pgtest_tobind.str).to eq('123')
        end
      end

      context 'adding header to a packet' do
        it 'calls #added_to_packet' do
          $global_var = false
          Packet.gen('PGTest::ToBind')
          expect($global_var).to be(true)
        end
      end

      context 'when adding to a packet' do
        before(:all) do
          class PacketTest < Base
            define_field :field, Types::Int8, default: ->(h) { h.packet ? h.packet.ip.tos : 255 }
          end
          Header.add_class PacketTest
          IP.bind PacketTest, protocol: 255
        end
        after(:all) { remove_binding IP, PacketTest}

        it 'subclass may access to previous headers' do
          pkt = Packet.gen('IP', tos: 45).add('PacketTest')
          expect(pkt.packettest.field).to eq(45)
        end
      end
    end
  end
end
