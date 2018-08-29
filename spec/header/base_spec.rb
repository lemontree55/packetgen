require_relative '../spec_helper'

$global_var = false

module PacketGen
  module Header
    describe Base do

      class TestBase < Base
        define_field :field1, Types::Int8
        define_field :field2, Types::Int8
        define_field :body, Types::String
      end

      class ToBind < Base
        define_field :field, Types::Int32, default: 1
        def added_to_packet(_packet)
          $global_var = true
        end
      end

      describe '.bind_header' do
        after(:each) { clear_bindings TestBase }

        it 'binds a header to another one with a single value' do
          TestBase.bind_header ToBind, field1: 55
          expect(TestBase).to know_header(ToBind).with(field1: 55)
          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(55)
          expect(pkt.testbase.field2).to eq(0)
        end

        it 'binds a header to another one with multiple field (or case)' do
          TestBase.bind_header ToBind, field1: 55, field2: 1
          expect(TestBase).to know_header(ToBind).with(field1: 55, field2: 1)
          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(55)
          expect(pkt.testbase.field2).to eq(1)
        end

        it 'binds a header to another one with multiple field (and case)' do
          TestBase.bind_header ToBind, op: :and, field1: 55, field2: 2
          expect(TestBase).to know_header(ToBind).with(field1: 55, field2: 2)
          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(55)
          expect(pkt.testbase.field2).to eq(2)
        end

        it 'binds a header to another one using a lambda' do
          TestBase.bind_header ToBind, field1: ->(v) { v.nil? ? 128 : v > 127 }
          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(128)
        end
      end

      describe '.bind' do
        after(:each) { clear_bindings TestBase }

        it 'binds a header with a single value' do
          TestBase.bind ToBind, field1: 55
          expect(TestBase).to know_header(ToBind).with(field1: 55)
          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(55)
          expect(pkt.testbase.field2).to eq(0)
        end

        it 'binds a header with multiple fields' do
          TestBase.bind ToBind, field1: 55, field2: 2
          expect(TestBase).to know_header(ToBind).with(field1: 55, field2: 2)
          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(55)
          expect(pkt.testbase.field2).to eq(2)
        end

        it 'binds a header using a lambda' do
          TestBase.bind ToBind, field1: ->(v) { v.nil? ? 128 : v > 127 }
          expect(TestBase).to_not know_header(ToBind).with(field1: 127)
          expect(TestBase).to know_header(ToBind).with(field1: 128)
          expect(TestBase).to know_header(ToBind).with(field1: 129)
          expect(TestBase).to know_header(ToBind).with(field1: 255)
          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(128)
        end

        it 'binds a header using procs' do
          TestBase.bind ToBind, procs: [->(h) { h.field1 = 42 },
                                        ->(h) { h.field1 == 42 && Types::Int32.new.read(h.body[0..3]).to_i > 0 }]
          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(42)

          pkt2 = Packet.parse(pkt.to_s, first_header: 'TestBase')
          expect(pkt2.is?('TestBase')).to be(true)
          expect(pkt2.is?('ToBind')).to be(true)
          expect(pkt2.testbase.body).to be_a(ToBind)

          pkt.tobind.field = 0
          pkt3 = Packet.parse(pkt.to_s, first_header: 'TestBase')
          expect(pkt3.is?('TestBase')).to be(true)
          expect(pkt3.is?('ToBind')).to be(false)
          expect(pkt3.testbase.body).to be_a(Types::String)
        end

        it 'binds a header with multiple possibility (multiple calls to .bind)' do
          TestBase.bind ToBind, field1: 55, field2: 2
          TestBase.bind ToBind, field1: 54, field2: 3
          expect(TestBase).to know_header(ToBind).with(field1: 55, field2: 2)
          expect(TestBase).to know_header(ToBind).with(field1: 54, field2: 3)

          pkt = Packet.new.add('TestBase').add('ToBind')
          expect(pkt.testbase.field1).to eq(55)
          expect(pkt.testbase.field2).to eq(2)
        end
      end

      context 'adding header to a packet' do
        it 'calls #added_to_packet' do
          $global_var = false
          Packet.gen('ToBind')
          expect($global_var).to be(true)
        end
      end
    end
  end
end
